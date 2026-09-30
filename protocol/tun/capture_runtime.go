package tun

import (
	"github.com/sagernet/sing-box/common/taskmonitor"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/service/oomkiller"
	"github.com/sagernet/sing-tun"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service"
)

// buildTunRuntime creates the TUN interface and stack without starting packet
// capture. It is reentrant: the capture coordinator calls it on every Activate
// after a previous Deactivate tore the runtime down. The TUN file descriptor
// cannot be reopened once NativeTun.Close runs, so a dormant TUN must be fully
// rebuilt rather than merely paused. The caller supplies tunOptions because the
// staged lifecycle path fills route addresses into a local copy first, while
// the coordinator path (auto_redirect always set) passes t.tunOptions directly.
func (t *Inbound) buildTunRuntime(tunOptions tun.Options) error {
	if t.tunIf != nil && t.tunStack != nil {
		return nil
	}
	var (
		tunInterface tun.Tun
		err          error
	)
	monitor := taskmonitor.New(t.logger, C.StartTimeout)
	monitor.Start("open interface")
	if t.platformInterface != nil && t.platformInterface.UsePlatformInterface() {
		tunInterface, err = t.platformInterface.OpenInterface(&tunOptions, t.platformOptions)
	} else {
		tunInterface, err = tun.New(tunOptions)
	}
	monitor.Finish()
	t.tunOptions.Name = tunOptions.Name
	if err != nil {
		return E.Cause(err, "configure tun interface")
	}
	t.logger.Trace("creating stack")
	t.tunIf = tunInterface
	if t.platformInterface != nil {
		err = t.platformInterface.ProcessPlatformOptions(t.platformOptions)
		if err != nil {
			closeError := t.tunIf.Close()
			t.tunIf = nil
			return E.Errors(E.Cause(err, "process platform options"), closeError)
		}
	}
	var includeAllNetworks bool
	if t.platformInterface != nil && t.platformInterface.UnderNetworkExtension() {
		includeAllNetworks = t.platformInterface.NetworkExtensionIncludeAllNetworks()
	}
	var memoryPressure func() tun.MemoryPressure
	oomKiller := service.FromContext[*oomkiller.Service](t.ctx)
	if oomKiller != nil {
		memoryPressure = oomKiller.MemoryPressure
	}
	tunStack, err := tun.NewStack(t.stack, tun.StackOptions{
		Context:                t.ctx,
		Tun:                    tunInterface,
		TunOptions:             t.tunOptions,
		UDPTimeout:             t.udpTimeout,
		ICMPTimeout:            C.ICMPTimeout,
		UDPMapping:             t.udpMapping,
		UDPFiltering:           t.udpFiltering,
		UDPNATMax:              t.udpNATMax,
		Handler:                t,
		Logger:                 t.logger,
		ForwarderBindInterface: C.IsDarwin,
		InterfaceFinder:        t.networkManager.InterfaceFinder(),
		IncludeAllNetworks:     includeAllNetworks,
		MemoryPressure:         memoryPressure,
	})
	if err != nil {
		return err
	}
	t.tunStack = tunStack
	return nil
}

// startTunCapture brings up packet capture on an already-built runtime: the
// stack, the TUN interface (which installs auto-route rules), and auto-redirect
// (iptables). It is the single activation point shared by the staged lifecycle
// and the capture coordinator.
func (t *Inbound) startTunCapture() error {
	if t.tunIf == nil || t.tunStack == nil {
		return E.New("TUN runtime is not built")
	}
	monitor := taskmonitor.New(t.logger, C.StartTimeout)
	monitor.Start("starting tun stack")
	err := t.tunStack.Start()
	monitor.Finish()
	if err != nil {
		return E.Cause(err, "starting tun stack")
	}
	monitor.Start("starting tun interface")
	err = t.tunIf.Start()
	monitor.Finish()
	if err != nil {
		return E.Cause(err, "starting TUN interface")
	}
	if t.autoRedirect != nil && !t.autoRedirectStarted {
		monitor.Start("initialize auto-redirect")
		err := t.autoRedirect.Start()
		monitor.Finish()
		if err != nil {
			return E.Cause(err, "auto-redirect")
		}
		t.autoRedirectStarted = true
	}
	t.captureActive = true
	t.logger.Info("capture started at ", t.tunOptions.Name)
	return nil
}

// teardownTunCapture removes all packet interception and releases the TUN file
// descriptor and its auto-route rules. After this the TUN is fully dormant: no
// rules remain to blackhole traffic belonging to the other capture backend.
// The autoRedirect object is reusable (Close then Start), so it is kept.
func (t *Inbound) teardownTunCapture() error {
	t.captureActive = false
	var err error
	if t.autoRedirect != nil && t.autoRedirectStarted {
		err = E.Errors(err, t.autoRedirect.Close())
		t.autoRedirectStarted = false
	}
	if t.tunStack != nil {
		err = E.Errors(err, t.tunStack.Close())
		t.tunStack = nil
	}
	if t.tunIf != nil {
		err = E.Errors(err, t.tunIf.Close())
		t.tunIf = nil
	}
	if err == nil {
		t.logger.Info("capture torn down")
	}
	return err
}
