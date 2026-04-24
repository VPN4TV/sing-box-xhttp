package libbox

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
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
			retErr = E.New("panic in Setup: ", fmt.Sprint(r))
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
	}
	return nil
}

func SetLocale(localeId string) error {
	if strings.Contains(localeId, "@") {
		localeId = strings.Split(localeId, "@")[0]
	}
	if !locale.Set(localeId) {
		return E.New("unsupported locale: ", localeId)
	}
	return nil
}

func Version() string {
	return C.Version
}

func GoVersion() string {
	return runtime.Version() + ", " + runtime.GOOS + "/" + runtime.GOARCH
}

func FormatBytes(length int64) string {
	return byteformats.FormatKBytes(uint64(length))
}

func FormatMemoryBytes(length int64) string {
	return byteformats.FormatMemoryKBytes(uint64(length))
}

func FormatDuration(duration int64) string {
	return log.FormatDuration(time.Duration(duration) * time.Millisecond)
}

func FormatBitrate(bps int64) string {
	return networkquality.FormatBitrate(bps)
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

func FormatNATMapping(value int32) string {
	return stun.NATMapping(value).String()
}

func FormatNATFiltering(value int32) string {
	return stun.NATFiltering(value).String()
}

func FormatFQDN(fqdn string) string {
	return dns.FqdnToDomain(fqdn)
}

func ProxyDisplayType(proxyType string) string {
	return C.ProxyDisplayName(proxyType)
}
