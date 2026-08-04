package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// unsetEnvVars clears the given env vars and restores them after the test.
func unsetEnvVars(t *testing.T, keys ...string) {
	t.Helper()
	for _, key := range keys {
		prev, exists := os.LookupEnv(key)
		os.Unsetenv(key)
		if exists {
			t.Cleanup(func() { os.Setenv(key, prev) })
		}
	}
}

func TestFromEnvVars_NilDefaults_UsesBuiltinDefaults(t *testing.T) {
	unsetEnvVars(t, "SERVER_PORT", "SERVER_ADDRESS")

	cfg := FromEnvVars(nil)

	assert.Equal(t, DefaultPort, cfg.Port)
	assert.Equal(t, DefaultAddress, cfg.Address)
}

func TestFromEnvVars_CustomDefaults_UsedWhenEnvAbsent(t *testing.T) {
	unsetEnvVars(t, "SERVER_PORT", "SERVER_ADDRESS")

	cfg := FromEnvVars(&Config{Port: "8080", Address: "0.0.0.0"})

	assert.Equal(t, "8080", cfg.Port)
	assert.Equal(t, "0.0.0.0", cfg.Address)
}

func TestFromEnvVars_EnvPort_OverridesDefault(t *testing.T) {
	unsetEnvVars(t, "SERVER_ADDRESS")
	t.Setenv("SERVER_PORT", "3000")

	cfg := FromEnvVars(nil)

	assert.Equal(t, "3000", cfg.Port)
	assert.Equal(t, DefaultAddress, cfg.Address)
}

func TestFromEnvVars_EnvAddress_OverridesDefault(t *testing.T) {
	unsetEnvVars(t, "SERVER_PORT")
	t.Setenv("SERVER_ADDRESS", "192.168.1.1")

	cfg := FromEnvVars(nil)

	assert.Equal(t, DefaultPort, cfg.Port)
	assert.Equal(t, "192.168.1.1", cfg.Address)
}

func TestFromEnvVars_BothEnvVars_OverrideBothDefaults(t *testing.T) {
	t.Setenv("SERVER_PORT", "4433")
	t.Setenv("SERVER_ADDRESS", "10.0.0.1")

	cfg := FromEnvVars(nil)

	assert.Equal(t, "4433", cfg.Port)
	assert.Equal(t, "10.0.0.1", cfg.Address)
}

func TestFromEnvVars_EnvVars_OverrideCustomDefaults(t *testing.T) {
	t.Setenv("SERVER_PORT", "5000")
	t.Setenv("SERVER_ADDRESS", "172.16.0.1")

	cfg := FromEnvVars(&Config{Port: "8080", Address: "0.0.0.0"})

	assert.Equal(t, "5000", cfg.Port)
	assert.Equal(t, "172.16.0.1", cfg.Address)
}
