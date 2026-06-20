//go:build !linux

package libbox

import "os"

// redirectCrashStderr is a no-op off Linux: the fd-2 capture (see the linux
// build) is only needed for the Android 32-bit GC-corruption diagnosis.
func redirectCrashStderr(f *os.File) {}
