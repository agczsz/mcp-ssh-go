package main

import (
	"fmt"
	"os"
	"strconv"
)

// Output-size cap for exec results. Unbounded command output (a multi-MB Slurm
// log, solver output, CSV) returned as a tool result can exceed the calling
// model's entire context window and kill the turn. Each stream (stdout, stderr)
// is therefore capped: on overflow the result is the first ~75% + last ~25% of
// the cap with a marker in between that tells the model how to narrow the
// command, so it can self-correct on the next call.
const (
	defaultMaxOutputBytes = 128 * 1024
	minMaxOutputBytes     = 1024
	maxMaxOutputBytes     = 512 * 1024
	maxDirEntries         = 2000
)

// clampOutputCap resolves the per-stream byte cap: the per-call override if
// given, else SSH_MCP_MAX_OUTPUT_BYTES, else the default — always bounded.
func clampOutputCap(override int) int {
	n := override
	if n <= 0 {
		n = defaultMaxOutputBytes
		if env := os.Getenv("SSH_MCP_MAX_OUTPUT_BYTES"); env != "" {
			if v, err := strconv.Atoi(env); err == nil && v > 0 {
				n = v
			}
		}
	}
	if n < minMaxOutputBytes {
		n = minMaxOutputBytes
	}
	if n > maxMaxOutputBytes {
		n = maxMaxOutputBytes
	}
	return n
}

// capWriter is an io.Writer that retains at most limit bytes: the first
// headLimit bytes verbatim plus a ring buffer of the most recent tailLimit
// bytes. Memory is bounded regardless of how much the command writes.
type capWriter struct {
	headLimit int
	tailLimit int
	head      []byte
	tail      []byte // ring buffer; tailPos is the next write position
	tailPos   int
	total     int64
}

func newCapWriter(limit int) *capWriter {
	head := limit * 3 / 4
	return &capWriter{headLimit: head, tailLimit: limit - head}
}

func (w *capWriter) Write(p []byte) (int, error) {
	n := len(p)
	w.total += int64(n)
	if room := w.headLimit - len(w.head); room > 0 {
		take := room
		if take > len(p) {
			take = len(p)
		}
		w.head = append(w.head, p[:take]...)
		p = p[take:]
	}
	if len(p) > 0 && w.tailLimit > 0 {
		if w.tail == nil {
			w.tail = make([]byte, w.tailLimit)
		}
		if len(p) >= w.tailLimit {
			copy(w.tail, p[len(p)-w.tailLimit:])
			w.tailPos = 0
		} else {
			c := copy(w.tail[w.tailPos:], p)
			copy(w.tail, p[c:])
			w.tailPos = (w.tailPos + len(p)) % w.tailLimit
		}
	}
	return n, nil
}

// result assembles the retained output. When nothing was dropped the original
// stream is returned intact; otherwise head + truncation marker + tail.
func (w *capWriter) result() (out string, truncated bool) {
	overflow := w.total - int64(len(w.head)) // bytes that went past head
	if overflow <= 0 {
		return string(w.head), false
	}
	var tail []byte
	if overflow >= int64(w.tailLimit) {
		tail = make([]byte, 0, w.tailLimit)
		tail = append(tail, w.tail[w.tailPos:]...)
		tail = append(tail, w.tail[:w.tailPos]...)
	} else {
		tail = w.tail[:overflow]
	}
	dropped := overflow - int64(len(tail))
	if dropped <= 0 {
		return string(w.head) + string(tail), false
	}
	marker := fmt.Sprintf(
		"\n[... %s truncated (returned first %s + last %s of %s total). Narrow with head/tail/grep -n, or redirect to a file and sample it. ...]\n",
		humanBytes(dropped), humanBytes(int64(len(w.head))), humanBytes(int64(len(tail))), humanBytes(w.total))
	return string(w.head) + marker + string(tail), true
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
