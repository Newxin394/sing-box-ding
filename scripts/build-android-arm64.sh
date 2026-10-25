#!/bin/sh
# build-android-arm64.sh — 编译 android/arm64 内核（sfmr 部署用）
#
# 取代了根目录四个硬编码 /var/minis 路径的历史脚本
# (build_a9.sh / build_v30.sh / build_tc.sh / migrate_build.sh)。
#
# 用法(仓库根目录):
#   sh scripts/build-android-arm64.sh                版本号取 constant.Version
#   sh scripts/build-android-arm64.sh 1.15.0-alpha.13-ding   自定义版本号
#   OUT=/tmp/sb sh scripts/build-android-arm64.sh    指定输出路径
set -e
cd "$(dirname "$0")/.."

# constant/version.go 里是 var Version = "unknown"，未传参时用 git describe 兜底
VER="${1:-$(sed -n 's/^var Version = "\(.*\)"/\1/p' constant/version.go)}"
case "$VER" in
  ""|unknown) VER="$(git describe --tags --always 2>/dev/null || echo dev)" ;;
esac
OUT="${OUT:-./sing-box-android}"

# with_ebpf: 纯 TC 入站(local=tc, shared=packet_rewrite)必需
# with_xhttp / with_tailscale: 节点协议与 tailcat 入站需要
TAGS="with_quic,with_dhcp,with_utls,with_clash_api,with_ebpf,with_xhttp,with_tailscale"

export GOOS=android GOARCH=arm64 GOARM64=v8.0 CGO_ENABLED=0 GOTOOLCHAIN=local

echo "版本: $VER"
echo "tags: $TAGS"
go build -trimpath -buildvcs=false -tags "$TAGS" \
  -ldflags "-X 'github.com/sagernet/sing-box/constant.Version=$VER' -s -w -buildid=" \
  -o "$OUT" ./cmd/sing-box

ls -la "$OUT"
