package libbox

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/sagernet/sing-box/common/networkquality"
	"github.com/sagernet/sing-box/common/stun"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/experimental/locale"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/service/oomkiller"
	"github.com/sagernet/sing/common/byteformats"
	E "github.com/sagernet/sing/common/exceptions"
)

var (
	sBasePath                string
	sWorkingPath             string
	sTempPath                string
	sUserID                  int
	sGroupID                 int
	sFixAndroidStack         bool
	sCommandServerListenPort uint16
	sCommandServerSecret     string
	sLogMaxLines             int
	sDebug                   bool
	sCrashReportSource       string
	sOOMKillerEnabled        bool
	sOOMKillerDisabled       bool
	sOOMMemoryLimit          int64
)

func init() {
	debug.SetPanicOnFault(true)
	debug.SetTraceback("all")
}

type SetupOptions struct {
	BasePath                string
	WorkingPath             string
	TempPath                string
	FixAndroidStack         bool
	CommandServerListenPort int32
	CommandServerSecret     string
	LogMaxLines             int
	Debug                   bool
	CrashReportSource       string
	OomKillerEnabled        bool
	OomKillerDisabled       bool
	OomMemoryLimit          int64
	// CrashLogPath is the file the Go runtime writes a crash report to when
	// the process is about to abort (debug.SetCrashOutput). Includes all
	// goroutine stacks, which the native unwinder can't recover from a
	// SIGABRT inside _cgo_topofstack. The Kotlin side reads this file on
	// next launch to surface the real cause via Play Vitals.
	CrashLogPath string
}

func applySetupOptions(options *SetupOptions) {
	sBasePath = options.BasePath
	sWorkingPath = options.WorkingPath
	sTempPath = options.TempPath

	sUserID = os.Getuid()
	sGroupID = os.Getgid()

	// TODO: remove after fixed
	// https://github.com/golang/go/issues/68760
	sFixAndroidStack = options.FixAndroidStack

	sCommandServerListenPort = uint16(options.CommandServerListenPort)
	sCommandServerSecret = options.CommandServerSecret
	sLogMaxLines = options.LogMaxLines
	sDebug = options.Debug
	sCrashReportSource = options.CrashReportSource
	ReloadSetupOptions(options)
}

func ReloadSetupOptions(options *SetupOptions) {
	sOOMKillerEnabled = options.OomKillerEnabled
	sOOMKillerDisabled = options.OomKillerDisabled
	sOOMMemoryLimit = options.OomMemoryLimit
	if sOOMKillerEnabled {
		if sOOMMemoryLimit == 0 && C.IsIos {
			sOOMMemoryLimit = oomkiller.DefaultAppleNetworkExtensionMemoryLimit
		}
		if sOOMMemoryLimit > 0 {
			debug.SetMemoryLimit(sOOMMemoryLimit * 3 / 4)
		} else {
			debug.SetMemoryLimit(math.MaxInt64)
		}
	} else {
		debug.SetMemoryLimit(math.MaxInt64)
	}
}

func Setup(options *SetupOptions) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			// Capture the Go stack — fmt.Sprint(r) alone gives only the
			// panic value (e.g. "runtime error: index out of range"),
			// which is useless for diagnostics on 32-bit TVs. The Kotlin
			// side's StackTraceElement injection then surfaces it in
			// Vitals frames verbatim.
			retErr = E.New("panic in Setup: ", fmt.Sprint(r), "\n", string(debug.Stack()))
		}
	}()
	applySetupOptions(options)
	// Multi-user Android TVs (Sony Bravia, Hisense, Haier MatrixTV) install
	// the app under user 0 but the runtime process executes as user 10. Path
	// /data/user/0/<pkg>/cache and /storage/emulated/0/Android/data/<pkg>/...
	// are owned by user 0 and the runtime user gets EACCES. Don't fail Setup
	// over storage permission errors — the in-memory libbox is still usable
	// (no crash log capture, but VPN works). The Kotlin side already mkdirs
	// these paths up front, so a benign EEXIST is also OK.
	if err := os.MkdirAll(sWorkingPath, 0o777); err != nil {
		fmt.Fprintf(os.Stderr, "libbox setup: working dir mkdir non-fatal: %v\n", err)
	}
	if err := os.MkdirAll(sTempPath, 0o777); err != nil {
		fmt.Fprintf(os.Stderr, "libbox setup: temp dir mkdir non-fatal: %v\n", err)
	}
	if err := redirectStderr(filepath.Join(sWorkingPath, "CrashReport-"+sCrashReportSource+".log")); err != nil {
		fmt.Fprintf(os.Stderr, "libbox setup: stderr redirect non-fatal: %v\n", err)
	}
	if options.CrashLogPath != "" {
		// Best-effort: open file for writing, hand it to the runtime. If
		// open fails we silently skip; the runtime keeps the fd open for
		// the lifetime of the process and writes a full goroutine dump
		// when it aborts.
		if f, err := os.OpenFile(options.CrashLogPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644); err == nil {
			if err := debug.SetCrashOutput(f, debug.CrashOptions{}); err != nil {
				fmt.Fprintf(os.Stderr, "libbox setup: SetCrashOutput non-fatal: %v\n", err)
				f.Close()
			}
		} else {
			fmt.Fprintf(os.Stderr, "libbox setup: open crash log non-fatal: %v\n", err)
		}
		// Capture the runtime's pre-throw stderr (the reportZombies/badPointer
		// preamble with the offending span's size class) into CrashLogPath
		// +".stderr". SetCrashOutput above records only the post-throw traceback
		// (crashFD, written once m.dying>0); the preamble prints earlier and
		// reaches fd 2 only. Redirecting fd 2 to its own file (not the crashFD
		// file) avoids the two-fd offset clobber. consumeCrashLog reads it.
		redirectCrashStderr(options.CrashLogPath)
	}
	return nil
}

func SetLocale(localeID string) error {
	if !locale.Set(localeID) {
		return E.New("unsupported locale: ", localeID)
	}
	return nil
}

// String-returning helpers are all wrapped in *StringBox to dodge the
// bulkBarrierPreWrite-unaligned-arguments panic on 32-bit ARM
// (golang/go#46893). FormatBytes in particular gets polled once a
// second from the foreground-service notification updater; a raw
// `string` return there meant every active session on a 32-bit TV did
// the unaligned write once a second, gradually corrupting the heap
// until GC tripped over it.
func Version() *StringBox {
	return wrapString(C.Version)
}

func GoVersion() *StringBox {
	return wrapString(runtime.Version() + ", " + runtime.GOOS + "/" + runtime.GOARCH)
}

// DebugGoroutineDump returns a snapshot of ALL goroutine stacks (the same
// output as a SIGQUIT traceback). Called from the Kotlin connect-watchdog when
// startOrReloadService doesn't return in time: it runs on its own cgo
// goroutine and runtime.Stack(all=true) snapshots every goroutine INCLUDING
// the blocked Box.Start one, so we can see exactly where a connect hang is
// stuck (field diagnosis for the boot-time / no-network hang) without device
// access. Buffer grown until it fits.
func DebugGoroutineDump() *StringBox {
	for size := 1 << 20; size <= 1<<23; size <<= 1 {
		buf := make([]byte, size)
		n := runtime.Stack(buf, true)
		if n < size {
			return wrapString(string(buf[:n]))
		}
	}
	buf := make([]byte, 1<<23)
	return wrapString(string(buf[:runtime.Stack(buf, true)]))
}

func FormatBytes(length int64) *StringBox {
	return wrapString(byteformats.FormatKBytes(uint64(length)))
}

func FormatMemoryBytes(length int64) *StringBox {
	return wrapString(byteformats.FormatMemoryKBytes(uint64(length)))
}

func FormatDuration(duration int64) *StringBox {
	return wrapString(log.FormatDuration(time.Duration(duration) * time.Millisecond))
}

func FormatBitrate(bps int64) *StringBox {
	return wrapString(networkquality.FormatBitrate(bps))
}

const NetworkQualityDefaultConfigURL = networkquality.DefaultConfigURL

const NetworkQualityDefaultMaxRuntimeSeconds = int32(networkquality.DefaultMaxRuntime / time.Second)

const (
	NetworkQualityAccuracyLow    = int32(networkquality.AccuracyLow)
	NetworkQualityAccuracyMedium = int32(networkquality.AccuracyMedium)
	NetworkQualityAccuracyHigh   = int32(networkquality.AccuracyHigh)
)

const (
	NetworkQualityPhaseIdle     = int32(networkquality.PhaseIdle)
	NetworkQualityPhaseDownload = int32(networkquality.PhaseDownload)
	NetworkQualityPhaseUpload   = int32(networkquality.PhaseUpload)
	NetworkQualityPhaseDone     = int32(networkquality.PhaseDone)
)

const STUNDefaultServer = stun.DefaultServer

const (
	STUNPhaseBinding      = int32(stun.PhaseBinding)
	STUNPhaseNATMapping   = int32(stun.PhaseNATMapping)
	STUNPhaseNATFiltering = int32(stun.PhaseNATFiltering)
	STUNPhaseDone         = int32(stun.PhaseDone)
)

const (
	NATMappingEndpointIndependent     = int32(stun.NATMappingEndpointIndependent)
	NATMappingAddressDependent        = int32(stun.NATMappingAddressDependent)
	NATMappingAddressAndPortDependent = int32(stun.NATMappingAddressAndPortDependent)
)

const (
	NATFilteringEndpointIndependent     = int32(stun.NATFilteringEndpointIndependent)
	NATFilteringAddressDependent        = int32(stun.NATFilteringAddressDependent)
	NATFilteringAddressAndPortDependent = int32(stun.NATFilteringAddressAndPortDependent)
)

func FormatNATMapping(value int32) *StringBox {
	return wrapString(stun.NATMapping(value).String())
}

func FormatNATFiltering(value int32) *StringBox {
	return wrapString(stun.NATFiltering(value).String())
}

func FormatFQDN(fqdn string) *StringBox {
	return wrapString(dns.FqdnToDomain(fqdn))
}

func ProxyDisplayType(proxyType string) *StringBox {
	return wrapString(C.ProxyDisplayName(proxyType))
}
