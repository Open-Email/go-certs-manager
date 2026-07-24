// Package safego runs goroutines with panic recovery so a panic in a background
// worker (maintenance loop, async issuance) is logged instead of crashing the
// host process.
package safego

import (
	"log/slog"
	"runtime/debug"
)

// Go runs fn in a new goroutine. If fn panics, the panic is logged with a stack
// trace and swallowed.
func Go(logger *slog.Logger, name string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("panic in goroutine",
					"goroutine", name,
					"panic", r,
					"stack", string(debug.Stack()),
				)
			}
		}()
		fn()
	}()
}
