#!/bin/sh
# check-ding-sync.sh — bump sing 依赖后，核对 vendored 的 ding.go 是否需同步
#
# 背景: protocol/http/ding.go 是上游 sing 的 protocol/http/client.go 的
# vendored 拷贝 + "ding-direct"(With-At) 扩展。上游改动不会让 ding.go 报错
# (静默失配), 故 bump sing 后跑一次本脚本核对。
#
# 用法(仓库根目录):
#   sh scripts/check-ding-sync.sh           人工模式: 打印差异供判断
#   sh scripts/check-ding-sync.sh --check   CI 模式: 差异涉及握手/认证逻辑即退出 1
#
# 差异应只含 ding 扩展(dingClient/dingHost/With-At/dingHeader/sHTTP)与
# 等价重构(重命名/else合并)以及 client.host 的就地赋值; 若出现握手逻辑行
# (http.ReadResponse/bufio/CachedConn/Proxy-Authorization/request.Write等)
# 变更, 则需把上游新逻辑手动同步进 ding.go。
set -e
cd "$(dirname "$0")/.."

CHECK_MODE=0
[ "$1" = "--check" ] && CHECK_MODE=1

VER=$(grep -E '^\s*github.com/sagernet/sing v' go.mod | awk '{print $2}')
[ -z "$VER" ] && { echo "❌ go.mod 中找不到 sing 版本"; exit 2; }

UP="$(go env GOMODCACHE)/github.com/sagernet/sing@${VER}/protocol/http/client.go"
[ -f "$UP" ] || { echo "❌ 未找到上游: $UP"; echo "   请先: go mod download github.com/sagernet/sing@$VER"; exit 2; }

echo "sing 版本: $VER"
echo "上游: $UP"
echo "本地: protocol/http/ding.go"

# 用临时文件而非 <(...) 进程替换: 后者是 bash 扩展, busybox ash / dash 会语法报错。
# 末尾 || true: 无差异(ding.go 与上游完全一致)时 grep 返回 1, 避免 set -e 提前退出。
#
# diff 必须带 -u。下面那行过滤是照 unified 格式的 + / - 前缀写的, 而普通 diff
# 输出的是 < / > 与 "3c3"/"9d8", 于是 grep -E '^[+-][^+-]' 永远匹配不到任何一行:
# 实测把握手行 http.ReadResponse 改坏, 过滤后仍然是 0 行, 脚本会一直报"健康"。
# 加 -u 后同一改动能稳定报出 59 行。
#
# 过滤必须是 ^[[:space:]]*// 而不是 ^//: 后者只去掉行首注释, 函数体内缩进的
# 注释会原样留在差异里(实测约占输出行数的 13%), 会把真正需要看的握手改动淹没。
UP_STRIPPED=$(mktemp)
LOCAL_STRIPPED=$(mktemp)
DIFF_LINES=$(mktemp)
CRITICAL_HITS=$(mktemp)
trap 'rm -f "$UP_STRIPPED" "$LOCAL_STRIPPED" "$DIFF_LINES" "$CRITICAL_HITS"' EXIT
grep -vE '^[[:space:]]*//|^$' "$UP" > "$UP_STRIPPED"
grep -vE '^[[:space:]]*//|^$' protocol/http/ding.go > "$LOCAL_STRIPPED"
diff -u "$UP_STRIPPED" "$LOCAL_STRIPPED" | grep -E '^[+-][^+-]' > "$DIFF_LINES" || true

DIFF_COUNT=$(wc -l < "$DIFF_LINES" | tr -d ' ')
echo "差异行数: $DIFF_COUNT (健康值约 82; 明显增大说明上游改动尚未同步)"

# 判定哪些差异属于"握手/认证逻辑"——这些行一旦变化, 必须人工把上游新逻辑搬进
# ding.go, 因为本 fork 无法在外部感知这类改动。
#
# 判据: 某个握手/认证关键词在差异里出现过, 而 ding.go 里一处都找不到 —— 这说明
# 上游往这条路径里写了新逻辑, ding.go 没跟。
#
# 只看差异的 - 侧不够, 这是实测踩到的坑: ding.go 是 client.go 的改写副本, 两边共有
# 的行(ReadResponse / MethodConnect / Proxy-Connection...)是上下文行, 带一个空格前缀,
# 不进 - 也不进 +。所以 - 侧只剩 "上游原样、被 ding 换掉" 的行, 比如
#
#   -	reader := std_bufio.NewReader(conn)      上游原样, ding 换成池化版
#   +	reader := acquireDingBufioReader(conn)
#
# 这类行在 ding.go 里找得到替换物, 不算问题; 但真正的漏同步 —— 上游新加一行
# http.ReadResponse(...), ding.go 没搬 —— 会出现在 + 侧, 只扫 - 侧就漏了(反证测试
# 确认过: 把 ding.go 的 ReadResponse 全删掉, 旧判据仍然 exit 0)。
#
# 所以两侧都扫, 以 "关键词在差异里出现 且 ding.go 里没有" 为唯一条件。
# bufio 不单列成 token: 它只出现在 std_bufio 的上下文里, 单列会让池化实现被误判。
CRITICAL_TOKENS='ReadResponse std_bufio CachedConn Proxy-Authorization request\.Write context\.AfterFunc http\.MethodConnect Proxy-Connection base64\.StdEncoding'

if [ "$CHECK_MODE" = 1 ]; then
  for token in $CRITICAL_TOKENS; do
    if grep -qE "$token" "$DIFF_LINES" && ! grep -qE "$token" protocol/http/ding.go; then
      echo "$token" >> "$CRITICAL_HITS"
    fi
  done
  if [ -s "$CRITICAL_HITS" ]; then
    echo
    echo "❌ upstream sing's HTTP handshake/auth calls are missing from ding.go:"
    echo
    cat "$CRITICAL_HITS"
    echo
    echo "  1. 对照上面的 token, 到 protocol/http/ding.go 里补上对应的上游逻辑"
    echo "  2. 重跑 sh scripts/check-ding-sync.sh 确认只剩 ding 扩展差异"
    exit 1
  fi
  echo "✅ 差异不涉及握手/认证逻辑, ding.go 无需动作"
  exit 0
fi

echo
echo "=== 差异 ==="
cat "$DIFF_LINES"
echo
echo "=== 判定提示 ==="
echo "若无输出或仅 ding/重命名相关 → ding.go 健康, 无需动作"
echo "若上游出现 ding.go 里完全没有的握手调用 (ReadResponse / CachedConn /"
echo "Proxy-Authorization / request.Write / context.AfterFunc 等) → 需手动同步到 ding.go"
echo
echo "CI 可用: sh scripts/check-ding-sync.sh --check"
