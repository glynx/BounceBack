package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/D00Movenok/BounceBack/internal/wrapper"
	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"
)

func prepareMany(
	rules []Rule,
	e wrapper.Entity,
	logger zerolog.Logger,
) error {
	var eg errgroup.Group
	for _, r := range rules {
		func(rr Rule) {
			eg.Go(func() error {
				err := rr.Prepare(e, logger)
				if err != nil {
					return fmt.Errorf("can't prepare %s: %w", rr, err)
				}
				return nil
			})
		}(r)
	}
	return eg.Wait() //nolint: wrapcheck // wrapped above
}

// compile a list of pattern strings
func compileRegexpList(patternsStrings []string) ([]*regexp.Regexp, error) {
	var (
		re  *regexp.Regexp
		l   []*regexp.Regexp
		err error
	)
	for _, patternString := range patternsStrings {
		re, err = regexp.Compile(patternString)
		if err != nil {
			return nil, fmt.Errorf("can't parse regexp: %w", err)
		}
		l = append(l, re)
	}

	return l, nil
}

func xorDecrypt(key []byte, data []byte) []byte {
	for i := 0; i < len(data); i++ {
		data[i] ^= key[i%len(key)]
	}
	return data
}

func netbiosDecode(data []byte, isLowercase bool) ([]byte, error) {
	if len(data)%2 != 0 || len(data) == 0 {
		return nil, ErrOddOrZero
	}

	var (
		start byte
		end   byte
	)
	if isLowercase {
		start = 'a'
		end = 'z'
	} else {
		start = 'A'
		end = 'Z'
	}
	for _, b := range data {
		if b < start || b > end {
			return nil, ErrCaseMismatch
		}
	}

	for i := 0; i < len(data); i += 2 {
		data[i/2] = ((data[i] - start) << 4) + //nolint:mnd
			((data[i+1] - start) & 0xF) //nolint:mnd
	}

	return data[:len(data)/2], nil
}

func matchByMask(s string, m string) bool {
	start := m[0] == '*'
	end := m[len(m)-1] == '*'
	switch {
	case start && end:
		return strings.Contains(s, m[1:len(m)-1])
	case start:
		return strings.HasSuffix(s, m[1:])
	case end:
		return strings.HasPrefix(s, m[:len(m)-1])
	default:
		return s == m
	}
}

func checksum8(data []byte) uint8 {
	var out uint8
	for _, b := range data {
		out += b
	}
	return out
}
