package interpolate

import (
	"regexp"
	"slices"
	"strings"
)

const (
	maxInterpolationDepth = 10
	maxExpandedValueBytes = 1 << 20  // 1 MiB per secret value
	maxTotalExpandedBytes = 16 << 20 // 16 MiB per Expand call
)

// varPattern matches either ${VAR_NAME} or {{VAR_NAME}}
var varPattern = regexp.MustCompile(`\$\{([a-zA-Z0-9_]+)\}|\{\{([a-zA-Z0-9_]+)\}\}`)

// HasReference returns true if the string contains any ${VAR} or {{VAR}} placeholder.
func HasReference(val string) bool {
	return strings.Contains(val, "${") || strings.Contains(val, "{{")
}

// ExtractReferences returns all unique variable names referenced in the string.
func ExtractReferences(val string) []string {
	matches := varPattern.FindAllStringSubmatch(val, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := make(map[string]bool)
	var refs []string
	for _, m := range matches {
		name := m[1]
		if name == "" {
			name = m[2]
		}
		if name != "" && !seen[name] {
			seen[name] = true
			refs = append(refs, name)
		}
	}
	return refs
}

// Expand resolves all ${KEY} or {{KEY}} references in secrets against other keys in the same map.
// It resolves nested references with cycle detection, depth limits, size caps, and deterministic
// single-pass template expansion (so literal ${...} tokens inside resolved values are not re-expanded).
func Expand(secrets map[string]string) map[string]string {
	result := make(map[string]string, len(secrets))
	if len(secrets) == 0 {
		return result
	}

	keys := make([]string, 0, len(secrets))
	for k := range secrets {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	memo := make(map[string]string, len(secrets))
	visiting := make(map[string]bool)
	totalBytes := 0

	var resolve func(key string, depth int) (val string, clean bool)
	resolve = func(key string, depth int) (string, bool) {
		if v, ok := memo[key]; ok {
			return v, true
		}
		raw, exists := secrets[key]
		if !exists {
			return "", true
		}
		if depth >= maxInterpolationDepth || !HasReference(raw) {
			return raw, depth < maxInterpolationDepth
		}

		visiting[key] = true
		defer delete(visiting, key)

		locs := varPattern.FindAllStringSubmatchIndex(raw, -1)
		if len(locs) == 0 {
			memo[key] = raw
			return raw, true
		}

		var b strings.Builder
		b.Grow(len(raw))
		pos := 0
		clean := true
		abortedSize := false

		for _, loc := range locs {
			// Append literal prefix before match
			prefix := raw[pos:loc[0]]
			if b.Len()+len(prefix) > maxExpandedValueBytes {
				abortedSize = true
				break
			}
			b.WriteString(prefix)

			match := raw[loc[0]:loc[1]]
			varName := ""
			if loc[2] >= 0 && loc[3] >= 0 {
				varName = raw[loc[2]:loc[3]]
			} else if loc[4] >= 0 && loc[5] >= 0 {
				varName = raw[loc[4]:loc[5]]
			}

			replacement := match
			if varName == key || visiting[varName] {
				clean = false
			} else if _, targetExists := secrets[varName]; targetExists {
				resolved, subClean := resolve(varName, depth+1)
				replacement = resolved
				if !subClean {
					clean = false
				}
			}

			if b.Len()+len(replacement) > maxExpandedValueBytes {
				abortedSize = true
				break
			}
			b.WriteString(replacement)
			pos = loc[1]
		}

		if abortedSize {
			return raw, false
		}

		suffix := raw[pos:]
		if b.Len()+len(suffix) > maxExpandedValueBytes {
			return raw, false
		}
		b.WriteString(suffix)

		out := b.String()
		if clean {
			memo[key] = out
		}
		return out, clean
	}

	for _, k := range keys {
		if totalBytes >= maxTotalExpandedBytes {
			result[k] = secrets[k]
			continue
		}
		val, _ := resolve(k, 0)
		if totalBytes+len(val) > maxTotalExpandedBytes {
			result[k] = secrets[k]
			totalBytes = maxTotalExpandedBytes
			continue
		}
		result[k] = val
		totalBytes += len(val)
	}

	return result
}
