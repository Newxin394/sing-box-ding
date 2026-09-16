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
echo "差异行数: $DIFF_COUNT (健康值约 57; 明显增大说明上游改动尚未同步)"

# 判定哪些差异属于"握手/认证逻辑"——这些行一旦变化, 必须人工把上游新逻辑搬进
# ding.go, 因为本 fork 无法在外部感知这类改动。
# 注意不要把这些也列进来: NewClient / Client / Options 的改名是 ding 扩展本身
# 造成的既有差异, 每次都会命中, 加进来会让 CI 永久变红。
CRITICAL='ReadResponse|std_bufio|bufio|CachedConn|Proxy-Authorization|request\.Write|context\.AfterFunc|http\.MethodConnect|Proxy-Connection|base64\.StdEncoding'

if [ "$CHECK_MODE" = 1 ]; then
  if grep -E "$CRITICAL" "$DIFF_LINES" > "$CRITICAL_HITS"; then
    echo
    echo "❌ 上游 sing 的 HTTP 握手/认证逻辑已变更, ding.go 需要手动同步:"
    echo
    cat "$CRITICAL_HITS"
    echo
    echo "  1. 对照上面的行, 把上游 client.go 的新逻辑搬进 protocol/http/ding.go"
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
echo "若出现 ReadResponse / bufio / CachedConn / Proxy-Authorization /"
echo "request.Write / context.AfterFunc 等行变更 → 需手动同步上游到 ding.go"
echo
echo "CI 可用: sh scripts/check-ding-sync.sh --check"
