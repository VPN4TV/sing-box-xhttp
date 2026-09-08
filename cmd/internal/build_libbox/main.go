package main

import (
	"archive/zip"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	_ "github.com/sagernet/gomobile"
	"github.com/sagernet/sing-box/cmd/internal/build_shared"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/rw"
	"github.com/sagernet/sing/common/shell"
)

var (
	debugEnabled bool
	target       string
	platform     string
	// withTailscale bool
)

func init() {
	flag.BoolVar(&debugEnabled, "debug", false, "enable debug")
	flag.StringVar(&target, "target", "android", "target platform")
	flag.StringVar(&platform, "platform", "", "specify platform")
	// flag.BoolVar(&withTailscale, "with-tailscale", false, "build tailscale for iOS and tvOS")
}

func main() {
	flag.Parse()

	build_shared.FindMobile()

	switch target {
	case "android":
		buildAndroid()
	case "apple":
		buildApple()
	}
}

var (
	sharedFlags []string
	debugFlags  []string
	sharedTags  []string
	darwinTags  []string
	// memcTags    []string
	notMemcTags []string
	debugTags   []string
)

func init() {
	sharedFlags = append(sharedFlags, "-trimpath")
	sharedFlags = append(sharedFlags, "-buildvcs=false")
	currentTag, err := build_shared.ReadTag()
	if err != nil {
		currentTag = "unknown"
	}
	sharedFlags = append(sharedFlags, "-ldflags", build_shared.LinkerFlags(currentTag, false))
	debugFlags = append(debugFlags, "-ldflags", build_shared.LinkerFlags(currentTag, true))

	// with_wireguard dropped: VPN4TV routes ALL WireGuard/AmneziaWG (wg://, .conf)
	// through the in-process wireproxy bridge (amnezia-vpn/amneziawg-go ->
	// SOCKS5; see experimental/libbox/wireproxy.go), which is independent of this
	// tag. The sing-box-native wireguard endpoint is never emitted, so the tag
	// only added dead code/deps. Re-add if a native wireguard outbound is needed.
	// Upstream's with_usbip / with_openvpn / with_openconnect are also omitted:
	// VPN4TV strips those subsystems from the clients (and they are exactly the
	// surface that triggers store review), so shipping them would be dead weight.
	sharedTags = append(sharedTags, "with_gvisor", "with_quic", "with_utls", "with_naive_outbound", "with_clash_api", "badlinkname", "tfogo_checklinkname0")
	// olcRTC (TCP over a WebRTC "call" on a whitelisted meeting service) costs
	// ~30 MB of pion/livekit; every Apple target and the 64-bit Android
	// builds carry it, the 32-bit Android build (TV boxes) does not — see
	// buildAndroid.
	darwinTags = append(darwinTags, "with_dhcp", "grpcnotrace", "with_olcrtc")
	// memcTags = append(memcTags, "with_tailscale")
	// Tailscale dropped: VPN4TV never uses the tailscale endpoint, and it drags
	// in go-json-experiment (via sagernet/tailscale/ipn) which fails to compile
	// on go1.27rc1 (undefined json.SkipFunc/DiscardUnknownMembers — the json/v2
	// API moved). Excluding it unblocks the go1.27 toolchain test and shrinks
	// libbox. Re-add if a tailscale-based feature is ever needed.
	// sharedTags = append(sharedTags, "with_tailscale", "ts_omit_logtail", "ts_omit_ssh", "ts_omit_drive", "ts_omit_taildrop", "ts_omit_webclient", "ts_omit_doctor", "ts_omit_capture", "ts_omit_kube", "ts_omit_aws", "ts_omit_synology", "ts_omit_bird")
	notMemcTags = append(notMemcTags, "with_low_memory")
	debugTags = append(debugTags, "debug")
}

type AndroidBuildConfig struct {
	AndroidAPI int
	OutputName string
	Tags       []string
}

func filterTags(tags []string, exclude ...string) []string {
	excludeMap := make(map[string]bool)
	for _, tag := range exclude {
		excludeMap[tag] = true
	}
	var result []string
	for _, tag := range tags {
		if !excludeMap[tag] {
			result = append(result, tag)
		}
	}
	return result
}

func checkJavaVersion() {
	var javaPath string
	javaHome := os.Getenv("JAVA_HOME")
	if javaHome == "" {
		javaPath = "java"
	} else {
		javaPath = filepath.Join(javaHome, "bin", "java")
	}

	javaVersion, err := shell.Exec(javaPath, "--version").ReadOutput()
	if err != nil {
		log.Fatal(E.Cause(err, "check java version"))
	}
	if !strings.Contains(javaVersion, "openjdk 17") {
		log.Fatal("java version should be openjdk 17")
	}
}

func getAndroidBindTarget() string {
	if platform != "" {
		return platform
	} else if debugEnabled {
		return "android/arm64"
	}
	return "android"
}

func buildAndroidVariant(config AndroidBuildConfig, bindTarget string) {
	args := []string{
		"bind",
		"-v",
		"-o", config.OutputName,
		"-target", bindTarget,
		"-androidapi", strconv.Itoa(config.AndroidAPI),
		"-javapkg=io.nekohasekai",
		"-libname=box",
	}

	if !debugEnabled {
		args = append(args, sharedFlags...)
	} else {
		args = append(args, debugFlags...)
	}

	args = append(args, "-tags", strings.Join(config.Tags, ","))
	args = append(args, "./experimental/libbox")

	command := exec.Command(build_shared.GoBinPath+"/gomobile", args...)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	err := command.Run()
	if err != nil {
		log.Fatal(err)
	}

	copyPath := filepath.Join("..", "sing-box-for-android", "app", "libs")
	if rw.IsDir(copyPath) {
		copyPath, _ = filepath.Abs(copyPath)
		err = rw.CopyFile(config.OutputName, filepath.Join(copyPath, config.OutputName))
		if err != nil {
			log.Fatal(err)
		}
		log.Info("copied ", config.OutputName, " to ", copyPath)
	}
}

func buildAndroid() {
	build_shared.FindSDK()
	checkJavaVersion()

	bindTarget := getAndroidBindTarget()

	// Build main variant. VPN4TV: API 23, not upstream's 24 — the app runs on
	// Android 6 TV boxes, and nothing on the Go side needs 24 (the upstream bump
	// came with a Kotlin-side change).
	mainTags := append([]string{}, sharedTags...)
	// mainTags = append(mainTags, memcTags...)
	if debugEnabled {
		mainTags = append(mainTags, debugTags...)
	}
	// VPN4TV: the 64-bit ABIs get olcrtc, the 32-bit ones (TV boxes, where the
	// library size is what hurts) do not. gomobile builds one feature set per
	// invocation, so the two halves are built separately and the 32-bit
	// libbox.so is then packed into the 64-bit AAR. The Java surface is the
	// same in both — the small build keeps every export and refuses at runtime.
	wide, narrow := splitAndroidTargets(bindTarget)
	if len(wide) == 0 || len(narrow) == 0 {
		tags := mainTags
		if len(wide) > 0 {
			tags = append(append([]string{}, mainTags...), "with_olcrtc")
		}
		buildAndroidVariant(AndroidBuildConfig{
			AndroidAPI: 23,
			OutputName: "libbox.aar",
			Tags:       tags,
		}, bindTarget)
	} else {
		buildAndroidVariant(AndroidBuildConfig{
			AndroidAPI: 23,
			OutputName: "libbox.aar",
			Tags:       append(append([]string{}, mainTags...), "with_olcrtc"),
		}, strings.Join(wide, ","))
		buildAndroidVariant(AndroidBuildConfig{
			AndroidAPI: 23,
			OutputName: "libbox-narrow.aar",
			Tags:       mainTags,
		}, strings.Join(narrow, ","))
		err := mergeAndroidLibraries("libbox.aar", "libbox-narrow.aar")
		if err != nil {
			log.Fatal(err)
		}
		_ = os.Remove("libbox-narrow.aar")
		log.Info("packed the 32-bit libbox.so (without olcrtc) into libbox.aar")
	}

	// Build legacy variant (SDK 21, no naive outbound)
	legacyTags := filterTags(sharedTags, "with_naive_outbound")
	// legacyTags = append(legacyTags, memcTags...)
	if debugEnabled {
		legacyTags = append(legacyTags, debugTags...)
	}
	buildAndroidVariant(AndroidBuildConfig{
		AndroidAPI: 21,
		OutputName: "libbox-legacy.aar",
		Tags:       legacyTags,
	}, bindTarget)
}

func buildApple() {
	var bindTarget string
	if platform != "" {
		bindTarget = platform
	} else if debugEnabled {
		bindTarget = "ios"
	} else {
		bindTarget = "ios,iossimulator,tvos,tvossimulator,macos"
	}

	args := []string{
		"bind",
		"-v",
		"-target", bindTarget,
		"-libname=box",
		"-tags-not-macos=with_low_memory",
		"-iosversion=15.0",
		"-macosversion=13.0",
		"-tvosversion=17.0",
	}
	//if !withTailscale {
	//	args = append(args, "-tags-macos="+strings.Join(memcTags, ","))
	//}

	if !debugEnabled {
		args = append(args, sharedFlags...)
	} else {
		args = append(args, debugFlags...)
	}

	tags := append(sharedTags, darwinTags...)
	//if withTailscale {
	//	tags = append(tags, memcTags...)
	//}
	if debugEnabled {
		tags = append(tags, debugTags...)
	}

	args = append(args, "-tags", strings.Join(tags, ","))
	args = append(args, "./experimental/libbox")

	command := exec.Command(build_shared.GoBinPath+"/gomobile", args...)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	err := command.Run()
	if err != nil {
		log.Fatal(err)
	}

	copyPath := filepath.Join("..", "sing-box-for-apple")
	if rw.IsDir(copyPath) {
		targetDir := filepath.Join(copyPath, "Libbox.xcframework")
		targetDir, _ = filepath.Abs(targetDir)
		os.RemoveAll(targetDir)
		os.Rename("Libbox.xcframework", targetDir)
		log.Info("copied to ", targetDir)
	}
}

// splitAndroidTargets separates a gomobile target list into the 64-bit ABIs
// (which get the full feature set) and the 32-bit ones. A bare "android" means
// all four.
func splitAndroidTargets(bindTarget string) (wide []string, narrow []string) {
	targets := strings.Split(bindTarget, ",")
	if bindTarget == "android" {
		targets = []string{"android/arm", "android/arm64", "android/386", "android/amd64"}
	}
	for _, target := range targets {
		switch strings.TrimSpace(target) {
		case "android/arm64", "android/amd64":
			wide = append(wide, target)
		case "android/arm", "android/386":
			narrow = append(narrow, target)
		}
	}
	return
}

// mergeAndroidLibraries copies every jni/<abi>/*.so from extraPath into
// mainPath, rewriting mainPath in place. Everything else (classes.jar, the
// manifest, proguard rules) comes from mainPath.
func mergeAndroidLibraries(mainPath string, extraPath string) error {
	extra, err := zip.OpenReader(extraPath)
	if err != nil {
		return err
	}
	defer extra.Close()
	main, err := zip.OpenReader(mainPath)
	if err != nil {
		return err
	}
	defer main.Close()

	merged, err := os.CreateTemp(filepath.Dir(mainPath), "libbox-merge-*.aar")
	if err != nil {
		return err
	}
	writer := zip.NewWriter(merged)
	copyEntry := func(file *zip.File) error {
		header := file.FileHeader
		out, err := writer.CreateHeader(&header)
		if err != nil {
			return err
		}
		in, err := file.Open()
		if err != nil {
			return err
		}
		defer in.Close()
		_, err = io.Copy(out, in)
		return err
	}
	isNativeLibrary := func(name string) bool {
		return strings.HasPrefix(name, "jni/") && strings.HasSuffix(name, ".so")
	}
	extraLibraries := make(map[string]bool)
	for _, file := range extra.File {
		if isNativeLibrary(file.Name) {
			extraLibraries[file.Name] = true
		}
	}
	for _, file := range main.File {
		if extraLibraries[file.Name] {
			return os.ErrExist // the same ABI in both halves means the split went wrong
		}
		if err := copyEntry(file); err != nil {
			return err
		}
	}
	for _, file := range extra.File {
		if !isNativeLibrary(file.Name) {
			continue
		}
		if err := copyEntry(file); err != nil {
			return err
		}
	}
	if err := writer.Close(); err != nil {
		return err
	}
	if err := merged.Close(); err != nil {
		return err
	}
	// CreateTemp makes the file private; the AAR is a build artifact, not a secret.
	if err := os.Chmod(merged.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(merged.Name(), mainPath)
}
