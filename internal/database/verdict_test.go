package database

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClearRejectsPreservesAccepts(t *testing.T) {
	db, err := New("", true)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, db.DB.Close())
	})

	const ip = "192.0.2.1"
	_, err = db.IncAccepts(ip)
	require.NoError(t, err)
	_, err = db.IncRejects(ip)
	require.NoError(t, err)
	_, err = db.IncRejects(ip)
	require.NoError(t, err)

	cleared, err := db.ClearRejects(ip)
	require.NoError(t, err)
	require.Equal(t, uint(2), cleared)

	verdict, err := db.GetVerdict(ip)
	require.NoError(t, err)
	require.Equal(t, uint(1), verdict.Accepts)
	require.Zero(t, verdict.Rejects)
}

func TestIncrementVerdictIsAtomic(t *testing.T) {
	db, err := New("", true)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, db.DB.Close())
	})

	const (
		ip         = "192.0.2.3"
		increments = 50
	)
	var wg sync.WaitGroup
	wg.Add(increments)
	for range increments {
		go func() {
			defer wg.Done()
			_, err := db.IncRejects(ip)
			require.NoError(t, err)
		}()
	}
	wg.Wait()

	verdict, err := db.GetVerdict(ip)
	require.NoError(t, err)
	require.Equal(t, uint(increments), verdict.Rejects)
}

func TestClearRejectsUnknownIP(t *testing.T) {
	db, err := New("", true)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, db.DB.Close())
	})

	cleared, err := db.ClearRejects("192.0.2.2")
	require.NoError(t, err)
	require.Zero(t, cleared)
}
