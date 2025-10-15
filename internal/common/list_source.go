package common

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
	"github.com/mitchellh/mapstructure"
)

type ListSource struct {
	Path  string   // if list is a file path
	Items []string // if list is []string 
}

// UnmarshalYAML allows both types
func (s *ListSource) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		// string => path
		var path string
		if err := value.Decode(&path); err != nil {
			return err
		}
		s.Path = strings.TrimSpace(path)
		s.Items = nil
		return nil
	case yaml.SequenceNode:
		// []string => inline array
		var items []string
		if err := value.Decode(&items); err != nil {
			return err
		}
		s.Items = items
		s.Path = ""
		return nil
	default:
		return errors.New(`"list" must be a string (path) or a sequence`)
	}
}

// Get the cleaned up lines (remove empty lines, comments and trailing spaces)
func (s ListSource) Resolve() ([]string, error) {
	if len(s.Items) > 0 {
		out := make([]string, 0, len(s.Items))
		for _, v := range s.Items {
			line := strings.TrimSpace(v)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			out = append(out, line)
		}
		return out, nil
	}
	if s.Path == "" {
		return nil, errors.New(`no "list" provided`)
	}
	f, err := os.Open(s.Path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}


func (s ListSource) Origin() string {
	if len(s.Items) > 0 {
		return "inline"
	}
	return s.Path
}


// DecodeHook returns a mapstructure hook that converts "list" values into ListSource.
// It accepts either string (file path) or []string (inline list).
func DecodeHook() mapstructure.DecodeHookFunc {
	target := reflect.TypeOf(ListSource{})
	return func(from, to reflect.Type, data any) (any, error) {
		if to != target {
			return data, nil
		}
		switch v := data.(type) {
		case string:
			return ListSource{Path: strings.TrimSpace(v)}, nil
		case []any:
			items := make([]string, 0, len(v))
			for i, el := range v {
				s, ok := el.(string)
				if !ok {
					return nil, fmt.Errorf(`"list" item #%d is not a string`, i)
				}
				items = append(items, s)
			}
			return ListSource{Items: items}, nil
		case []string:
			return ListSource{Items: v}, nil
		default:
			return nil, fmt.Errorf(`"list" must be string (path) or []string, got %T`, data)
		}
	}
}


// Option allows customizing the decoder configuration.
type Option func(*mapstructure.DecoderConfig)

// WithHook composes an additional DecodeHook into the decoder config.
func WithHook(h mapstructure.DecodeHookFunc) Option {
	return func(c *mapstructure.DecoderConfig) {
		if c.DecodeHook == nil {
			c.DecodeHook = h
		} else {
			c.DecodeHook = mapstructure.ComposeDecodeHookFunc(c.DecodeHook, h)
		}
	}
}

// WithTagName overrides the struct tag name (default: "mapstructure").
func WithTagName(tag string) Option {
	return func(c *mapstructure.DecoderConfig) { c.TagName = tag }
}

// DecodeParams decodes src into dst and enables the list_source hook.
// Typical usage: dst is a *Params struct for a rule.
func DecodeParams(src map[string]any, dst any, opts ...Option) error {
	cfg := &mapstructure.DecoderConfig{
		Result:           dst,
		TagName:          "mapstructure",
		ZeroFields:       true,
		WeaklyTypedInput: false,
		DecodeHook:       DecodeHook(),
	}
	for _, o := range opts {
		o(cfg)
	}
	dec, err := mapstructure.NewDecoder(cfg)
	if err != nil {
		return err
	}
	return dec.Decode(src)
}