package adapter

// ConfigChecker validates the runtime configuration before it is applied.
// It is exposed as a service so that components which can trigger a reload
// (for example the Clash API) refuse the request when the on-disk
// configuration would not start, instead of bringing the instance down.
type ConfigChecker interface {
	CheckConfig() error
}
