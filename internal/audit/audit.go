package audit

import (
	"io"

	"github.com/rs/zerolog"
)

var logger = zerolog.Nop()

// Configure sends structured audit events to w.
func Configure(w io.Writer) {
	logger = zerolog.New(w).With().Timestamp().Logger()
}

// Event starts a structured audit event.
func Event(name string) *zerolog.Event {
	return logger.Info().Str("event", name)
}
