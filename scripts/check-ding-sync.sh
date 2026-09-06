#!/bin/sh
# check-ding-sync.sh — bump sing 依赖后，核对 vendored 的 ding.go 是否需同步
#
# 背景: protocol/http/ding.go 是上游 sing 的 protocol/http/client.go 的
# vendored 拷贝 + "ding-direct"(With-At) 扩展。上游改动不会让 ding.go 报错
# (静默失配), 故 bump sing 后跑一次本脚本核对。
#
# 用法(仓库根目录): sh scripts/check-ding-sync.sh
# 它把上游 client.go 与本地 ding.go 去掉顶部说明注释后 diff, 输出变更行。
# 判定靠人: 变更应只含 ding 扩展(dingClient/dingHost/With-At/dingHeader)与
# 等价重构(重命名/else合并); 若出现握手逻辑行
# (http.ReadResponse/bufio/CachedConn/Proxy-Authorization/request.Write等)
# 变更, 则需把上游新逻辑手动同步进 ding.go。
set -e
cd "$(dirname "$0")/.."

VER=$(grep -E '^\s*github.com/sagernet/sing v' go.mod | awk '{print $2}')
[ -z "$VER" ] && { echo "❌ go.mod 中找不到 sing 版本"; exit 2; }

UP="$(go env GOMODCACHE)/github.com/sagernet/sing@${VER}/protocol/http/client.go"
[ -f "$UP" ] || { echo "❌ 未找到上游: $UP"; echo "   请先: go mod download github.com/sagernet/sing@$VER"; exit 2; }

echo "sing 版本: $VER"
echo "上游: $UP"
echo "本地: protocol/http/ding.go"
echo
echo "=== 差异(去掉 ding.go 顶部说明注释后的变更行) ==="
echo "(ding扩展/重命名差异=正常; 握手逻辑行变更=需同步上游)"
echo
diff \
  <(grep -vE '^//|^$' "$UP") \
  <(grep -vE '^//|^$' protocol/http/ding.go) \
  | grep -E '^[+-][^+-]'
echo
echo "=== 判定提示 ==="
echo "若无输出或仅 ding/重命名相关 → ding.go 健康, 无需动作"
echo "若出现 ReadResponse / bufio / CachedConn / Proxy-Authorization /"
echo "request.Write / context.AfterFunc 等行变更 → 需手动同步上游到 ding.go"
