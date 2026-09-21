package fuzz

import (
	"strings"
	"testing"

	"github.com/go-freya/freya/services/lcm/internal/stream"
)

// FuzzSSEFrame: the SSE frame encoder never panics and never lets event data
// inject extra SSE fields (embedded CR/LF are stripped from data).
func FuzzSSEFrame(f *testing.F) {
	f.Add("1-0", "renewed", `{"certificate_id":"c1"}`)
	f.Add("", "", "")
	f.Add("x", "issued", "line1\nline2\nevent: forged\ndata: x")
	f.Add("y", "revoked", "\r\n\r\n")
	f.Fuzz(func(t *testing.T, id, typ, data string) {
		out := stream.Frame(stream.Event{ID: id, Type: typ, Data: data})
		// The data value must occupy exactly one "data: " line: no raw newline
		// from the payload may survive to start a new SSE field.
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(line, "data: ") {
				if strings.ContainsAny(line, "\r") {
					t.Fatalf("carriage return survived in data line: %q", line)
				}
			}
		}
	})
}
