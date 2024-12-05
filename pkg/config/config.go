package config

type Config struct {
	HttpPort int    `env:"RDNS_HTTP_PORT"`
	LogLevel string `env:"RDNS_LOG_LEVEL"`
	// valid values: getaddrinfo, packet
	Resolvers []string `env:"RDNS_RESOLVERS" envSeparator:","`
}

const (
	ResolverGetAddrInfo = "getaddrinfo"
	ResolverPacket      = "packet"
)

var DefaultConfig = Config{
	HttpPort:  8080,
	LogLevel:  "info",
	Resolvers: []string{ResolverGetAddrInfo, ResolverPacket},
}
