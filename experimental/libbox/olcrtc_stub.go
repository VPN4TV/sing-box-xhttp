//go:build !with_olcrtc

package libbox

import "errors"

// VPN4TV: the build without the olcrtc runtime (32-bit ARM, see build_libbox).
// Same exported names as olcrtc.go so the mobile bindings do not differ.

const olcrtcBuiltIn = false

var errOlcrtcNotBuilt = errors.New("olcrtc is not available in this build")

// StartOlcrtcBridge refuses, after validating the config so a broken profile is
// reported as such rather than blamed on the build.
func StartOlcrtcBridge(configJSON string) error {
	if _, err := parseOlcrtcConfig(configJSON); err != nil {
		return err
	}
	olcrtcLog("start refused: %v", errOlcrtcNotBuilt)
	return errOlcrtcNotBuilt
}

// StopOlcrtcBridge is a no-op here.
func StopOlcrtcBridge() error {
	return nil
}
