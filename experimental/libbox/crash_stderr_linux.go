//go:build linux

package libbox

import (
	"os"

	"golang.org/x/sys/unix"
)

// redirectCrashStderr points fd 2 at a DEDICATED file (path+".stderr") so the
// Go runtime's pre-throw diagnostics are captured without being clobbered.
//
// On Android the runtime sends all print() output (incl. the
// reportZombies/badPointer preamble that carries the offending span's size
// class via gcDumpObject) to fd 2 via writeErrData -> write(2,...). The
// post-throw traceback additionally goes to the SetCrashOutput fd, but the
// PREAMBLE prints before m.dying is set, so it reaches fd 2 ONLY. Pointing fd 2
// at the SAME file as SetCrashOutput (the first attempt) failed: they are two
// fds with independent offsets, so the traceback (crashFD, offset 0) overwrote
// the preamble (fd 2, offset 0). A separate file gives fd 2 its own clean
// stream = preamble + traceback. consumeCrashLog uploads it.
//
// Safe/permanent: only the near-silent runtime stderr is captured; app logs use
// the platform logger. Returns the opened file kept alive for the dup'd fd 2.
func redirectCrashStderr(path string) {
	f, err := os.Create(path + ".stderr")
	if err != nil {
		return
	}
	_ = unix.Dup3(int(f.Fd()), 2, 0)
	// fd 2 now refers to f's open file description; closing the os.File handle
	// leaves fd 2 valid (independent dup).
	_ = f.Close()
}
