#!/bin/sh
set -e
cd /var/minis/shared/singme-build
export GOOS=android GOARCH=arm64 GOARM64=v8.0 CGO_ENABLED=0 GOTOOLCHAIN=local
VER="1.15.0-alpha.9-xhttp-tc-refind"
LD="-X github.com/sagernet/sing-box/constant.Version=${VER} -X runtime.godebugDefault=cryptocustomrand=1,tlssecpmlkem=0,urlstrictcolons=0 -checklinkname=0 -s -w -buildid="
TAGS="with_quic,with_dhcp,with_utls,with_clash_api,with_ebpf,with_xhttp,with_tailscale,badlinkname,tfogo_checklinkname0"
echo "开始编译: $VER"
go build -p=1 -trimpath -ldflags "$LD" -tags "$TAGS" -o sing-box-a9-align ./cmd/sing-box
echo "BUILD rc=$?"
ls -la sing-box-a9-align
