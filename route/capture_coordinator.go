//go:build with_ebpf && (linux || android)

package route

import (
	"context"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/capture"
	"github.com/sagernet/sing-box/log"
)

type captureCoordinatorService struct {
	logger  log.ContextLogger
	network *NetworkManager
	policy  capture.NetworkPolicy
	coord   *capture.Coordinator
	access  sync.Mutex
	last    string
}

var _ adapter.LifecycleService = (*captureCoordinatorService)(nil)
var _ adapter.InterfaceUpdateListener = (*captureCoordinatorService)(nil)

func newCaptureCoordinatorService(ctx context.Context, logger log.ContextLogger, network *NetworkManager, tcOwner, tunOwner capture.Owner) *captureCoordinatorService {
	return &captureCoordinatorService{
		logger:  logger,
		network: network,
		policy:  capture.DefaultNetworkPolicy(),
		coord:   capture.New(tcOwner, tunOwner, capture.Options{Debounce: 3 * time.Second}),
	}
}

func (s *captureCoordinatorService) Name() string { return "capture-coordinator" }

func (s *captureCoordinatorService) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStarted {
		return nil
	}
	return s.initializeCurrent()
}

func (s *captureCoordinatorService) Close() error {
	if s == nil || s.coord == nil {
		return nil
	}
	return s.coord.Close()
}

func (s *captureCoordinatorService) InterfaceUpdated(ctx context.Context) {
	if s == nil || ctx.Err() != nil {
		return
	}
	_ = s.requestCurrent()
}

func (s *captureCoordinatorService) initializeCurrent() error {
	s.access.Lock()
	defer s.access.Unlock()
	if s.network == nil || s.coord == nil {
		return nil
	}
	defaultInterface := s.network.DefaultNetworkInterface()
	mode, class, ok := s.policy.Select(defaultInterface, s.network.NetworkInterfaces())
	if !ok {
		return nil
	}
	s.logger.Info("capture coordinator: initial interface ", defaultInterface.Name, " class=", class, " mode=", mode)
	return s.coord.Initialize(mode)
}

func (s *captureCoordinatorService) requestCurrent() error {
	s.access.Lock()
	defer s.access.Unlock()
	if s.network == nil || s.coord == nil {
		return nil
	}
	defaultInterface := s.network.DefaultNetworkInterface()
	mode, class, ok := s.policy.Select(defaultInterface, s.network.NetworkInterfaces())
	if !ok {
		s.logger.Debug("capture coordinator: unknown default interface; retain current owner")
		return nil
	}
	name := ""
	if defaultInterface != nil {
		name = defaultInterface.Name
	}
	if name == s.last && s.coord.Current() == mode {
		return nil
	}
	s.last = name
	s.logger.Info("capture coordinator: interface ", name, " class=", class, " mode=", mode)
	s.coord.RequestMode(mode)
	return nil
}

func (s *captureCoordinatorService) CurrentMode() capture.Mode {
	if s == nil || s.coord == nil {
		return capture.ModeNone
	}
	return s.coord.Current()
}
