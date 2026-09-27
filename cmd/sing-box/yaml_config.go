package main

import (
	"bytes"
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"
)

// yamlToJSON converts YAML config content to JSON bytes, then the existing
// JSON decoding chain (UnmarshalExtendedContext) takes over.
//
// Format rule: YAML files only support '#' comments (yaml.v3 native). A '//'
// comment inside a YAML file is not valid YAML and will fail to parse with a
// clear error instead of being silently stripped. Use .json (JSONC) if you
// prefer '//' or '/* */' comments.
func yamlToJSON(content []byte) ([]byte, error) {
	var root any
	if err := yaml.Unmarshal(content, &root); err != nil {
		return nil, fmt.Errorf("parse YAML: %w", err)
	}
	root = normalizeYAMLValue(root)
	jsonContent, err := json.Marshal(root)
	if err != nil {
		return nil, fmt.Errorf("marshal YAML to JSON: %w", err)
	}
	return jsonContent, nil
}

// normalizeYAMLValue converts yaml.v3 decoded values into JSON-marshalable
// forms:
//   - map[string]any stays as-is (yaml.v3 already decodes keys as strings)
//   - map[any]any (older or nested decode paths) is converted recursively
//   - int / int64 / uint64 stay numeric (json.Marshal handles them; uint64
//     large values would error, so they are converted via float64)
//   - float64 passes through (yaml.v3 default for large/ambiguous numbers)
//   - []any is normalized recursively
func normalizeYAMLValue(value any) any {
	switch v := value.(type) {
	case map[string]any:
		for key, item := range v {
			v[key] = normalizeYAMLValue(item)
		}
		return v
	case map[any]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			out[fmt.Sprintf("%v", key)] = normalizeYAMLValue(item)
		}
		return out
	case []any:
		for i, item := range v {
			v[i] = normalizeYAMLValue(item)
		}
		return v
	case uint64:
		if v <= 1<<53 {
			return int64(v)
		}
		return float64(v)
	case int64, int:
		return v
	default:
		return v
	}
}

// isYAMLPath reports whether the given config path should be treated as YAML.
func isYAMLPath(path string) bool {
	if path == "stdin" {
		return false
	}
	return bytes.HasSuffix([]byte(path), []byte(".yaml")) || bytes.HasSuffix([]byte(path), []byte(".yml"))
}

// isYAMLEntry reports whether a directory entry name should be read as YAML.
func isYAMLEntry(name string) bool {
	return bytes.HasSuffix([]byte(name), []byte(".yaml")) || bytes.HasSuffix([]byte(name), []byte(".yml"))
}
