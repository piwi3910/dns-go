package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/piwi3910/dns-go/pkg/config"
)

func TestDefaultConfig(t *testing.T) {
	t.Parallel()
	cfg := config.DefaultConfig()

	if cfg.Server.ListenAddress != ":8083" {
		t.Errorf("Expected default listen address :8083, got %s", cfg.Server.ListenAddress)
	}

	if !cfg.Server.EnableTCP {
		t.Error("Expected TCP to be enabled by default")
	}

	if cfg.Cache.MessageCache.MaxSizeMB != 128 {
		t.Errorf("Expected default message cache size 128MB, got %d", cfg.Cache.MessageCache.MaxSizeMB)
	}

	if cfg.Cache.RRsetCache.MaxSizeMB != 256 {
		t.Errorf("Expected default RRset cache size 256MB, got %d", cfg.Cache.RRsetCache.MaxSizeMB)
	}

	if cfg.Resolver.Mode != "forwarding" {
		t.Errorf("Expected default mode 'forwarding', got %s", cfg.Resolver.Mode)
	}
}

func TestLoadFromFile(t *testing.T) {
	t.Parallel()

	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
server:
  listen_address: ":5353"
  num_workers: 4
  enable_tcp: false
  pprof_address: ""
  graceful_shutdown_timeout: 5s
  stats_report_interval: 60s

cache:
  message_cache:
    max_size_mb: 64
    num_shards: 32
  rrset_cache:
    max_size_mb: 128
    num_shards: 64
  prefetch:
    enabled: false
    threshold_hits: 50
    threshold_ttl_percent: 0.2
  min_ttl: 30s
  max_ttl: 12h
  negative_ttl: 30m

resolver:
  mode: "recursive"
  upstreams:
    - "9.9.9.9:53"
  root_hints_file: "/etc/dns/root.hints"
  max_recursion_depth: 20
  query_timeout: 3s
  enable_coalescing: false

logging:
  level: "debug"
  format: "json"
  enable_query_log: true
`
	err := os.WriteFile(configPath, []byte(configContent), 0o644)
	if err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	cfg, err := config.LoadFromFile(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify server config
	if cfg.Server.ListenAddress != ":5353" {
		t.Errorf("Expected listen address :5353, got %s", cfg.Server.ListenAddress)
	}
	if cfg.Server.NumWorkers != 4 {
		t.Errorf("Expected 4 workers, got %d", cfg.Server.NumWorkers)
	}
	if cfg.Server.EnableTCP {
		t.Error("Expected TCP to be disabled")
	}
	if cfg.Server.PprofAddress != "" {
		t.Errorf("Expected empty pprof address, got %s", cfg.Server.PprofAddress)
	}
	if cfg.Server.GracefulShutdownTimeout != 5*time.Second {
		t.Errorf("Expected 5s shutdown timeout, got %s", cfg.Server.GracefulShutdownTimeout)
	}

	// Verify cache config
	if cfg.Cache.MessageCache.MaxSizeMB != 64 {
		t.Errorf("Expected message cache 64MB, got %d", cfg.Cache.MessageCache.MaxSizeMB)
	}
	if cfg.Cache.MessageCache.NumShards != 32 {
		t.Errorf("Expected 32 message cache shards, got %d", cfg.Cache.MessageCache.NumShards)
	}
	if cfg.Cache.RRsetCache.MaxSizeMB != 128 {
		t.Errorf("Expected RRset cache 128MB, got %d", cfg.Cache.RRsetCache.MaxSizeMB)
	}
	if cfg.Cache.Prefetch.Enabled {
		t.Error("Expected prefetch to be disabled")
	}

	// Verify resolver config
	if cfg.Resolver.Mode != "recursive" {
		t.Errorf("Expected mode 'recursive', got %s", cfg.Resolver.Mode)
	}
	if len(cfg.Resolver.Upstreams) != 1 || cfg.Resolver.Upstreams[0] != "9.9.9.9:53" {
		t.Errorf("Expected upstream 9.9.9.9:53, got %v", cfg.Resolver.Upstreams)
	}
	if cfg.Resolver.RootHintsFile != "/etc/dns/root.hints" {
		t.Errorf("Expected root hints path, got %s", cfg.Resolver.RootHintsFile)
	}

	// Verify logging config
	if cfg.Logging.Level != "debug" {
		t.Errorf("Expected log level 'debug', got %s", cfg.Logging.Level)
	}
	if cfg.Logging.Format != "json" {
		t.Errorf("Expected log format 'json', got %s", cfg.Logging.Format)
	}
	if !cfg.Logging.EnableQueryLog {
		t.Error("Expected query log to be enabled")
	}
}

func TestLoadFromFile_NotFound(t *testing.T) {
	t.Parallel()

	_, err := config.LoadFromFile("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
}

func TestLoadFromFileOrDefault(t *testing.T) {
	t.Parallel()

	// Test with non-existent file - should return defaults
	cfg, err := config.LoadFromFileOrDefault("/nonexistent/config.yaml")
	if err != nil {
		t.Fatalf("Expected no error for non-existent file, got: %v", err)
	}

	// Should have default values
	if cfg.Server.ListenAddress != ":8083" {
		t.Errorf("Expected default listen address, got %s", cfg.Server.ListenAddress)
	}
}

func TestConfigValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		modify      func(*config.Config)
		expectError bool
	}{
		{
			name:        "Valid default config",
			modify:      func(c *config.Config) {},
			expectError: false,
		},
		{
			name: "Invalid worker count",
			modify: func(c *config.Config) {
				c.Server.NumWorkers = 0
			},
			expectError: true,
		},
		{
			name: "Invalid message cache shards (not power of 2)",
			modify: func(c *config.Config) {
				c.Cache.MessageCache.NumShards = 65
			},
			expectError: true,
		},
		{
			name: "Invalid RRset cache shards (not power of 2)",
			modify: func(c *config.Config) {
				c.Cache.RRsetCache.NumShards = 100
			},
			expectError: true,
		},
		{
			name: "Invalid resolver mode",
			modify: func(c *config.Config) {
				c.Resolver.Mode = "invalid"
			},
			expectError: true,
		},
		{
			name: "Valid recursive mode",
			modify: func(c *config.Config) {
				c.Resolver.Mode = "recursive"
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := config.DefaultConfig()
			tt.modify(cfg)
			err := cfg.Validate()
			if (err != nil) != tt.expectError {
				t.Errorf("Validate() error = %v, expectError = %v", err, tt.expectError)
			}
		})
	}
}

func TestSaveToFile(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "output.yaml")

	cfg := config.DefaultConfig()
	cfg.Server.ListenAddress = ":5353"
	cfg.Resolver.Mode = "recursive"

	err := cfg.SaveToFile(configPath)
	if err != nil {
		t.Fatalf("Failed to save config: %v", err)
	}

	// Load it back and verify
	loaded, err := config.LoadFromFile(configPath)
	if err != nil {
		t.Fatalf("Failed to load saved config: %v", err)
	}

	if loaded.Server.ListenAddress != ":5353" {
		t.Errorf("Expected listen address :5353, got %s", loaded.Server.ListenAddress)
	}
	if loaded.Resolver.Mode != "recursive" {
		t.Errorf("Expected mode 'recursive', got %s", loaded.Resolver.Mode)
	}
}

func TestLoadFromFile_InvalidYAML(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "invalid.yaml")

	// Write invalid YAML
	err := os.WriteFile(configPath, []byte("invalid: yaml: content: ["), 0o644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	_, err = config.LoadFromFile(configPath)
	if err == nil {
		t.Error("Expected error for invalid YAML")
	}
}

func TestLoadFromFile_InvalidConfig(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "invalid_config.yaml")

	// Write config with invalid values
	configContent := `
server:
  num_workers: 0
cache:
  message_cache:
    num_shards: 64
  rrset_cache:
    num_shards: 128
resolver:
  mode: "forwarding"
`
	err := os.WriteFile(configPath, []byte(configContent), 0o644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	_, err = config.LoadFromFile(configPath)
	if err == nil {
		t.Error("Expected error for invalid config")
	}
}

func TestIsPowerOfTwo(t *testing.T) {
	t.Parallel()

	// Test via validation
	cfg := config.DefaultConfig()

	// Valid powers of 2
	validValues := []int{1, 2, 4, 8, 16, 32, 64, 128, 256}
	for _, v := range validValues {
		cfg.Cache.MessageCache.NumShards = v
		cfg.Cache.RRsetCache.NumShards = 128 // Keep this valid
		if err := cfg.Validate(); err != nil {
			t.Errorf("Expected %d to be valid (power of 2), got error: %v", v, err)
		}
	}

	// Invalid values (not powers of 2)
	invalidValues := []int{0, 3, 5, 6, 7, 9, 10, 15, 17, 65, 100}
	for _, v := range invalidValues {
		cfg.Cache.MessageCache.NumShards = v
		if err := cfg.Validate(); err == nil {
			t.Errorf("Expected %d to be invalid (not power of 2)", v)
		}
	}
}
