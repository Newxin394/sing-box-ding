#!/bin/sh
set -e
cd /var/minis/workspace/align/sbding

export GOROOT=/opt/go126
export PATH=/opt/go126/bin:$PATH
export GOOS=android
export GOARCH=arm64
export GOARM64=v8.0
export CGO_ENABLED=0

VERSION="1.15.0-alpha.6-xhttp-tc"
# with_gvisor dropped: sing-tun's built-in stack is the default, tag is a no-op.
# with_tailscale: enables protocol/tailscale (tailcat) + tailssh.
TAGS="with_quic,with_dhcp,with_utls,with_clash_api,with_ebpf,with_xhttp,with_tailscale"

echo "=== go version ==="
go version

echo "=== building with tags: $TAGS ==="
go build -trimpath \
  -buildvcs=false \
  -tags "$TAGS" \
  -ldflags "-X 'github.com/sagernet/sing-box/constant.Version=$VERSION' -s -w -buildid=" \
  -o /var/minis/workspace/align/sbding/sing-box.tc \
  ./cmd/sing-box

echo "=== build done ==="
ls -la /var/minis/workspace/align/sbding/sing-box.tc
md5sum /var/minis/workspace/align/sbding/sing-box.tc
