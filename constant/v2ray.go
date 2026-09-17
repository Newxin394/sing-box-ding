package constant

const (
	V2RayTransportTypeHTTP        = "http"
	V2RayTransportTypeWebsocket   = "ws"
	V2RayTransportTypeQUIC        = "quic"
	V2RayTransportTypeGRPC        = "grpc"
	V2RayTransportTypeHTTPUpgrade = "httpupgrade"
	// lx: XHTTP transport (Xray-compatible), registered behind build tag with_xhttp
	V2RayTransportTypeXHTTP = "xhttp"
)
