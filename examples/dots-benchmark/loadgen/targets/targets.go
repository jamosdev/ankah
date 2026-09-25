// Package targets parses the fixed list of demo vhosts that the load
// generators drive. The list is small and fixed on purpose: this tool only
// ever aims at the two protection frontends of the self-contained Compose
// example, resolved through the demo edge, and never at an arbitrary host.
package targets

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Target is one named frontend and the base URL that reaches it.
type Target struct {
	Name    string
	BaseURL string
}

// URL joins the target's base with a request path such as "/pi?n=1".
func (t Target) URL(path string) string {
	if path == "" {
		return t.BaseURL
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return t.BaseURL + path
}

// Parse reads a "name=url,name=url" list. Order is preserved so callers can
// rely on strict round-robin issuance across the parsed targets. Names must
// be unique and each URL must have a scheme and host.
func Parse(spec string) ([]Target, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, errors.New("empty target list")
	}
	var out []Target
	seen := make(map[string]bool)
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, raw, ok := strings.Cut(part, "=")
		name = strings.TrimSpace(name)
		raw = strings.TrimSpace(raw)
		if !ok || name == "" || raw == "" {
			return nil, fmt.Errorf("target %q must be name=url", part)
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("target %q has an invalid url", part)
		}
		if seen[name] {
			return nil, fmt.Errorf("duplicate target name %q", name)
		}
		seen[name] = true
		out = append(out, Target{Name: name, BaseURL: strings.TrimRight(raw, "/")})
	}
	if len(out) == 0 {
		return nil, errors.New("no targets parsed")
	}
	return out, nil
}
