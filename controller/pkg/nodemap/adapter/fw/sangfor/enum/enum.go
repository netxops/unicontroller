package enum

type ApiPath string

const (
	Info                  = ApiPath("/api/v1/namespaces/@namespace/info")
	SystemVersion         = ApiPath("/api/v1/namespaces/@namespace/systemversion")
	Interfaces            = ApiPath("/api/v1/namespaces/@namespace/interfaces")
	IPGroups              = ApiPath("/api/v1/namespaces/@namespace/ipgroups")
	Services              = ApiPath("/api/v1/namespaces/@namespace/services")
	Securitys             = ApiPath("/api/v1/namespaces/@namespace/securitys")
	Appcontrols           = ApiPath("/api/v1/namespaces/@namespace/appcontrols/policys")
	Zones                 = ApiPath("/api/v1/namespaces/@namespace/zones")
	StaticRoutes          = ApiPath("/api/v1/namespaces/@namespace/staticroutes")
	PBRs                  = ApiPath("/api/v1/namespaces/@namespace/pbrs")
	Routes                = ApiPath("/api/v1/namespaces/@namespace/routes")
	NATs                  = ApiPath("/api/v1/namespaces/@namespace/nats")
)

type StructType string

const (
	NETOBJECT = StructType("NETOBJECT")
	SERVICE   = StructType("SERVICE")
	POLICY    = StructType("POLICY")
	ZONE      = StructType("ZONE")
	ROUTE     = StructType("ROUTE")
	NAT       = StructType("NAT")
)

