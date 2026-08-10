package main

// VPN4TV: report descriptor usage so a leak is visible in the log instead of
// only as a crash.
//
// A tester's daemon exhausted its descriptors within an hour of ordinary use and
// died with "too many open files", taking the machine's routing with it. Neither
// the core nor the daemon leaks in isolation — reproduced with vless, hysteria2,
// abandoned connections and an attached application, all flat — so whatever
// leaks needs the running tunnel, which cannot be reproduced without root. This
// makes the next occurrence self-diagnosing: the log says how fast descriptors
// grow and whether goroutines grow with them (connections leaking) or not
// (files or sockets opened without a goroutine behind them).

import (
	"context"
	"os"
	"runtime"
	"time"

	"github.com/sagernet/sing-box/log"
)

const (
	fdWatchInterval = time.Minute
	// Quiet until it actually looks wrong: a healthy daemon with a tunnel and an
	// attached client sits in the low hundreds.
	fdWatchThreshold = 512
)

// openFileCount counts this process's descriptors. /dev/fd on darwin and
// /proc/self/fd on linux both list one entry per descriptor; anywhere else this
// returns -1 and the watcher stays quiet.
func openFileCount() int {
	for _, directory := range []string{"/dev/fd", "/proc/self/fd"} {
		entries, err := os.ReadDir(directory)
		if err != nil {
			continue
		}
		// ReadDir itself holds one descriptor open while listing.
		return len(entries) - 1
	}
	return -1
}

// watchFileDescriptors logs descriptor usage once it crosses the threshold, and
// again on every doubling, so a steady leak leaves a trail without a healthy
// daemon writing anything at all.
func watchFileDescriptors(ctx context.Context, logger log.ContextLogger) {
	ticker := time.NewTicker(fdWatchInterval)
	defer ticker.Stop()
	reportAt := fdWatchThreshold
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		count := openFileCount()
		if count < 0 {
			return // unsupported platform, nothing to watch
		}
		if count < reportAt {
			continue
		}
		logger.Warn(
			"open file descriptors: ", count,
			", goroutines: ", runtime.NumGoroutine(),
			" (a steady rise here ends in \"too many open files\")",
		)
		reportAt = count * 2
	}
}
