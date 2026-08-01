package main

import (
	"strings"
	"testing"
)

func TestCapWriterUnderLimit(t *testing.T) {
	w := newCapWriter(1024)
	in := strings.Repeat("a", 500)
	_, _ = w.Write([]byte(in))
	out, truncated := w.result()
	if truncated || out != in {
		t.Fatalf("expected intact output, got truncated=%v len=%d", truncated, len(out))
	}
}

// Output larger than head but within the total limit must come back intact:
// part of it lives in the ring buffer but nothing was dropped.
func TestCapWriterHeadPlusPartialTail(t *testing.T) {
	w := newCapWriter(1024) // head 768, tail 256
	in := "start" + strings.Repeat("x", 900-10) + "endinralph"
	_, _ = w.Write([]byte(in))
	out, truncated := w.result()
	if truncated {
		t.Fatal("nothing was dropped; must not report truncation")
	}
	if out != in {
		t.Fatalf("output corrupted: got len %d want %d", len(out), len(in))
	}
}

func TestCapWriterTruncates(t *testing.T) {
	w := newCapWriter(1024) // head 768, tail 256
	head := strings.Repeat("H", 768)
	mid := strings.Repeat("M", 10000)
	tail := strings.Repeat("T", 256)
	// Write in awkward chunk sizes to exercise ring wraparound.
	full := head + mid + tail
	for i := 0; i < len(full); i += 333 {
		end := i + 333
		if end > len(full) {
			end = len(full)
		}
		_, _ = w.Write([]byte(full[i:end]))
	}
	out, truncated := w.result()
	if !truncated {
		t.Fatal("expected truncation")
	}
	if !strings.HasPrefix(out, head) {
		t.Fatal("head not preserved verbatim")
	}
	if !strings.HasSuffix(out, tail) {
		t.Fatalf("tail not preserved; last 40 bytes: %q", out[len(out)-40:])
	}
	if !strings.Contains(out, "truncated (returned first") {
		t.Fatal("marker missing")
	}
}

func TestCapWriterSingleHugeWrite(t *testing.T) {
	w := newCapWriter(1024)
	full := strings.Repeat("A", 768) + strings.Repeat("B", 50000) + strings.Repeat("Z", 256)
	_, _ = w.Write([]byte(full))
	out, truncated := w.result()
	if !truncated {
		t.Fatal("expected truncation")
	}
	if !strings.HasSuffix(out, strings.Repeat("Z", 256)) {
		t.Fatal("tail wrong after single oversized write")
	}
	if w.total != int64(len(full)) {
		t.Fatalf("total miscounted: %d != %d", w.total, len(full))
	}
}

func TestClampOutputCap(t *testing.T) {
	for _, tc := range []struct{ in, want int }{
		{0, defaultMaxOutputBytes},
		{-5, defaultMaxOutputBytes},
		{500, minMaxOutputBytes},
		{64 * 1024, 64 * 1024},
		{10 << 20, maxMaxOutputBytes},
	} {
		if got := clampOutputCap(tc.in); got != tc.want {
			t.Errorf("clampOutputCap(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestClampOutputCapEnvDefault(t *testing.T) {
	t.Setenv("SSH_MCP_MAX_OUTPUT_BYTES", "65536")
	if got := clampOutputCap(0); got != 65536 {
		t.Errorf("env default not honored: got %d", got)
	}
	// Explicit per-call override still wins over the env default.
	if got := clampOutputCap(2048); got != 2048 {
		t.Errorf("override ignored with env set: got %d", got)
	}
	t.Setenv("SSH_MCP_MAX_OUTPUT_BYTES", "999999999")
	if got := clampOutputCap(0); got != maxMaxOutputBytes {
		t.Errorf("env default not clamped: got %d", got)
	}
}
