package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// Config holds all WAF configuration sections.
type Config struct {
	Proxy      ProxyConfig      `mapstructure:"proxy"`
	ClickHouse ClickHouseConfig `mapstructure:"clickhouse"`
	Logging    LoggingConfig    `mapstructure:"logging"`
}

// ProxyConfig holds reverse proxy settings.
type ProxyConfig struct {
	ListenAddr string `mapstructure:"listen_addr"`
	BackendURL string `mapstructure:"backend_url"`
}

// ClickHouseConfig holds ClickHouse connection settings.
type ClickHouseConfig struct {
	Addr     string `mapstructure:"addr"`
	Database string `mapstructure:"database"`
}

// LoggingConfig holds logging settings.
type LoggingConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
}

// Load reads configuration from the given file path, with env override support.
func Load(path string) (*Config, error) {
	v := viper.New()

	v.SetConfigFile(path)
	v.SetEnvPrefix("WAF")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	return &cfg, nil
}
