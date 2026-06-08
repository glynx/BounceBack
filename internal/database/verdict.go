package database

import (
	"errors"
	"fmt"

	badger "github.com/dgraph-io/badger/v3"
)

const (
	VerdictPrefix string = "ip-verdict-"

	VerdictNone = iota
	VerdictAccept
	VerdictReject
)

type Verdict struct {
	Accepts uint
	Rejects uint
}

func (db *DB) GetVerdict(ip string) (*Verdict, error) {
	v, err := getCache[Verdict](db, ip, VerdictPrefix)
	if err != nil && !errors.Is(err, badger.ErrKeyNotFound) {
		return nil, fmt.Errorf("can't get cached verdicts: %w", err)
	}
	if v == nil {
		return &Verdict{}, nil
	}
	return v, nil
}

func (db *DB) IncAccepts(ip string) (*Verdict, error) {
	v, err := updateCache(db, ip, VerdictPrefix, func(v *Verdict) {
		v.Accepts++
	})
	if err != nil {
		return nil, fmt.Errorf("can't increase accepts: %w", err)
	}
	return v, nil
}

func (db *DB) IncRejects(ip string) (*Verdict, error) {
	v, err := updateCache(db, ip, VerdictPrefix, func(v *Verdict) {
		v.Rejects++
	})
	if err != nil {
		return nil, fmt.Errorf("can't increase rejects: %w", err)
	}
	return v, nil
}

// ClearRejects removes an IP's permanent-reject state without changing its
// accept history. It returns the number of rejects that were cleared.
func (db *DB) ClearRejects(ip string) (uint, error) {
	var previous uint
	_, err := updateCache(db, ip, VerdictPrefix, func(v *Verdict) {
		previous = v.Rejects
		v.Rejects = 0
	})
	if err != nil {
		return 0, fmt.Errorf("can't reset rejects: %w", err)
	}
	return previous, nil
}
