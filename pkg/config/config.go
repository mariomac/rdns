package config

type Config struct {
	LogLevel string `env:"RDNS_LOG_LEVEL"`
	// valid values: getaddrinfo, packet
	Resolvers []string `env:"RDNS_RESOLVERS"`
}

const (
	ResolverGetAddrInfo = "getaddrinfo"
	ResolverPacket      = "packet"
)

var DefaultConfig = Config{
	LogLevel:  "info",
	Resolvers: []string{ResolverGetAddrInfo, ResolverPacket},
}
