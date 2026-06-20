//go:build linux

package libbox

import (
	"os"

	"golang.org/x/sys/unix"
)

// redirectCrashStderr points fd 2 (stderr) at the crash-output file so the Go
// runtime's PRE-throw diagnostics are captured, not just the post-throw
// traceback that debug.SetCrashOutput records.
//
// reportZombies and badPointer (the GC heap-corruption detectors) print the
// offending span's size class and per-object alloc/free state via print()
// BEFORE calling throw(); that output goes to fd 2 (→ logcat on Android) and is
// otherwise lost. The size class is what pins down which struct's pointer field
// is being corrupted — on the 32-bit ARM heap-corruption cluster the bad
// pointer is consistently at object offset 0xc, but the struct can't be
// identified without the element size. Capturing fd 2 into the same crash file
// makes the next such crash carry that detail. Safe to keep in production: it
// only redirects the (normally near-silent) runtime stderr; sing-box's own logs
// go through the platform logger, not fd 2.
func redirectCrashStderr(f *os.File) {
	_ = unix.Dup3(int(f.Fd()), 2, 0)
}
