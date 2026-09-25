// Package envcfg reads configuration from environment variables with
// defaults. A present but malformed value is a configuration error rather
// than a silently substituted default, so a typo in a Compose file surfaces
// at startup instead of changing the load in a way nobody notices.
package envcfg

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// String returns the value of key, or def when key is unset or empty.
func String(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

// Int returns the integer value of key, or def when key is unset or empty.
func Int(key string, def int) (int, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %v", key, err)
	}
	return n, nil
}

// Float returns the floating point value of key, or def when key is unset or
// empty.
func Float(key string, def float64) (float64, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def, nil
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %v", key, err)
	}
	return f, nil
}

// Duration returns the duration value of key (Go duration syntax, for
// example "5s"), or def when key is unset or empty.
func Duration(key string, def time.Duration) (time.Duration, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %v", key, err)
	}
	return d, nil
}
