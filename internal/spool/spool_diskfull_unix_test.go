//go:build unix

package spool_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"github.com/perplexityai/numbat/internal/spool"
)

const (
	spoolDiskFullHelper = "NUMBAT_SPOOL_DISKFULL_HELPER"
	spoolDiskFullPath   = "NUMBAT_SPOOL_DISKFULL_PATH"
	spoolDiskFullLimit  = "NUMBAT_SPOOL_DISKFULL_LIMIT"
	recordBefore        = "{\"record_type\":\"event\",\"event_id\":\"before\"}\n"
	recordAfter         = "{\"record_type\":\"event\",\"event_id\":\"after\"}\n"
)

// TestPutOnFullDiskCommitsNothing reproduces the failure that corrupted the
// legacy append file: a write that cannot grow its backing file. A short or
// failed append left a partial NDJSON line that the next record concatenated
// with. bbolt commits are atomic, so a Put that cannot grow the database must
// leave the store byte-identical to its pre-Put state and stay usable once space
// is available.
//
// RLIMIT_FSIZE, set in a child process so the cap cannot disturb the test
// harness, makes any file growth fail deterministically without a real full
// filesystem. A multi-megabyte record forces bbolt to grow the database past the
// cap during commit.
func TestPutOnFullDiskCommitsNothing(t *testing.T) {
	if os.Getenv(spoolDiskFullHelper) == "1" {
		runDiskFullPutHelper()
		return
	}

	path := filepath.Join(t.TempDir(), "records.spool")
	store := spool.New(path)
	if err := store.Put([]byte(recordBefore)); err != nil {
		t.Fatalf("seed record: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat spool: %v", err)
	}

	// Cap the child at the current database size so any growth during commit
	// fails, then attempt a record far larger than any bbolt pre-allocation.
	cmd := exec.Command(os.Args[0], "-test.run=^TestPutOnFullDiskCommitsNothing$")
	cmd.Env = append(os.Environ(),
		spoolDiskFullHelper+"=1",
		spoolDiskFullPath+"="+path,
		spoolDiskFullLimit+"="+strconv.FormatInt(info.Size(), 10),
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("child Put unexpectedly succeeded under a file-size cap: %s", out)
	}
	if !bytes.Contains(out, []byte("put-failed")) {
		t.Fatalf("child did not report a failed Put: %s", out)
	}

	// The failed Put must have committed none of its bytes: the store still holds
	// exactly the seed record, with no partial or trailing fragment.
	assertSpoolRecords(t, store, recordBefore)

	// The store remains usable once space is available; the next record appends
	// cleanly after the seed record rather than gluing onto a partial write.
	if err := store.Put([]byte(recordAfter)); err != nil {
		t.Fatalf("Put after recovered space: %v", err)
	}
	assertSpoolRecords(t, store, recordBefore, recordAfter)
}

func runDiskFullPutHelper() {
	// Exceeding RLIMIT_FSIZE raises SIGXFSZ, whose default action kills the
	// process; ignore it so the offending write returns EFBIG instead.
	signal.Ignore(syscall.SIGXFSZ)
	limit, err := strconv.ParseInt(os.Getenv(spoolDiskFullLimit), 10, 64)
	if err != nil {
		reportDiskFullHelper("bad-limit:", err)
	}
	rlimit := syscall.Rlimit{Cur: uint64(limit), Max: uint64(limit)}
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &rlimit); err != nil {
		reportDiskFullHelper("setrlimit-failed:", err)
	}
	record := make([]byte, 0, 4<<20)
	record = append(record, []byte("{\"record_type\":\"event\",\"event_id\":\"big\",\"payload\":\"")...)
	record = append(record, bytes.Repeat([]byte("a"), 4<<20)...)
	record = append(record, []byte("\"}\n")...)
	if err := spool.New(os.Getenv(spoolDiskFullPath)).Put(record); err != nil {
		reportDiskFullHelper("put-failed:", err)
	}
	reportDiskFullHelper("put-succeeded", nil)
}

// reportDiskFullHelper writes one status line the parent test matches on, then
// exits: success on the "put-succeeded" marker, failure otherwise.
func reportDiskFullHelper(marker string, cause error) {
	if cause != nil {
		_, _ = fmt.Fprintln(os.Stdout, marker, cause)
		os.Exit(1)
	}
	_, _ = fmt.Fprintln(os.Stdout, marker)
	os.Exit(0)
}

func assertSpoolRecords(t *testing.T, store spool.Store, want ...string) {
	t.Helper()
	batch, err := store.Peek(64 << 20)
	if err != nil {
		t.Fatalf("peek spool: %v", err)
	}
	if len(batch.Records) != len(want) {
		t.Fatalf("queued %d record(s), want %d: %q", len(batch.Records), len(want), batch.Records)
	}
	for i, record := range want {
		if !bytes.Equal(batch.Records[i], []byte(record)) {
			t.Fatalf("queued record %d = %q, want %q", i, batch.Records[i], record)
		}
	}
}
