#!/bin/sh
# B方案: 用官方 testing HEAD (e85872e91aa8, 配 sing-tun@97d11460f2ea = a9同commit)
# 破坏式覆盖 17 个 device/调用方文件, 然后按 a9 参数编译。
cd /var/minis/shared/singme-build || exit 1

echo "=== [0] openconnect 定制标记词确认 (diff已证与官方0行差,应为通用词) ==="
grep -niE 'ebpf|bypass|直连|with-at|with_at|免流|cns|free.traffic' transport/openconnect/configuration.go | head -3

echo ""
echo "=== [1] off_head 覆盖 17 文件 (官方权威版) ==="
cnt=0
for rel in $(cd /tmp/off_head && find . -name '*.go' | sed 's|^\./||'); do
  dst="/var/minis/shared/singme-build/$rel"
  mkdir -p "$(dirname "$dst")"
  cp "/tmp/off_head/$rel" "$dst"
  cnt=$((cnt+1))
done
echo "  覆盖 $cnt 个文件"

echo ""
echo "=== [2] 验证覆盖后 device 与 endpoint 配套 (都应是新字段 PacketFrontHeadroom) ==="
echo -n "  device.go   : "; grep -c 'PacketFrontHeadroom' transport/device/device.go
echo -n "  endpoint.go : "; grep -c 'PacketFrontHeadroom' protocol/masque/endpoint.go
echo -n "  残留旧字段 PacketHeadroom: (device.Options里) "; grep -rn 'PacketHeadroom int' transport/device/device.go | wc -l

echo ""
echo "=== [3] go.mod 4依赖确认 = a9 版本 ==="
grep -E 'sagernet/(sing|sing-tun|tailscale|wireguard-go) v' go.mod

echo ""
echo "=== [4] 编译 (android arm64 + a9 tags + 版本注入) ==="
export GOOS=android GOARCH=arm64 GOARM64=v8.0 CGO_ENABLED=0 GOTOOLCHAIN=local
go build -trimpath \
  -ldflags "-X github.com/sagernet/sing-box/constant.Version=1.15.0-alpha.9-xhttp-tc-refind -X runtime.godebugDefault=cryptocustomrand=1,tlssecpmlkem=0,urlstrictcolons=0 -checklinkname=0 -s -w -buildid=" \
  -tags "with_quic,with_dhcp,with_utls,with_clash_api,with_ebpf,with_xhttp,with_tailscale,badlinkname,tfogo_checklinkname0" \
  -o sing-box-a9-B ./cmd/sing-box > /tmp/buildB.log 2>&1
rc=$?
echo "  build rc=$rc"
if [ $rc -ne 0 ]; then
  echo "  --- 错误 (tail 30) ---"
  tail -30 /tmp/buildB.log
else
  echo "  --- 编译成功 ---"
  ls -la sing-box-a9-B
fi
