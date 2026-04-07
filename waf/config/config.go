package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds all WAF configuration sections.
type Config struct {
	Proxy      ProxyConfig      `mapstructure:"proxy"`
	Analysis   AnalysisConfig   `mapstructure:"analysis"`
	ClickHouse ClickHouseConfig `mapstructure:"clickhouse"`
	Logging    LoggingConfig    `mapstructure:"logging"`
	Detection  DetectionConfig  `mapstructure:"detection"`
}

// DetectionConfig holds detection engine settings.
type DetectionConfig struct {
	RulesFile      string                 `mapstructure:"rules_file"`
	LogThreshold   float32                `mapstructure:"log_threshold"`
	BlockThreshold float32                `mapstructure:"block_threshold"`
	Enabled        bool                   `mapstructure:"enabled"`
	Allowlist      []AllowlistEntryConfig `mapstructure:"allowlist"`
}

// AllowlistEntryConfig holds a single allowlist entry from config.
type AllowlistEntryConfig struct {
	Comment    string            `mapstructure:"comment"`
	IPs        []string          `mapstructure:"ips"`
	Paths      []string          `mapstructure:"paths"`
	Headers    map[string]string `mapstructure:"headers"`
	UserAgents []string          `mapstructure:"user_agents"`
	Params     map[string]string `mapstructure:"params"`
	RuleIDs    []string          `mapstructure:"rule_ids"`
}

// ProxyConfig holds reverse proxy settings.
type ProxyConfig struct {
	ListenAddr string `mapstructure:"listen_addr"`
	BackendURL string `mapstructure:"backend_url"`
}

// AnalysisConfig holds request analysis settings.
type AnalysisConfig struct {
	MaxBodySize     int `mapstructure:"max_body_size"`
	MaxDecodePasses int `mapstructure:"max_decode_passes"`
}

// ClickHouseConfig holds ClickHouse connection settings.
type ClickHouseConfig struct {
	Addr          string        `mapstructure:"addr"`
	Database      string        `mapstructure:"database"`
	BatchSize     int           `mapstructure:"batch_size"`
	FlushInterval time.Duration `mapstructure:"flush_interval"`
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
