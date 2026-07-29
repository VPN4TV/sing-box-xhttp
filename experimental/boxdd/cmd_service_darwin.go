package main

// VPN4TV: launchd support for the desktop client. Upstream ships the daemon as
// a Windows service or a systemd unit installed by the Linux package; macOS had
// neither, so the app could never start its own tunnel and the DMG would have
// been useless without a manual sudo.
//
// The binary is copied to /Library/PrivilegedHelperTools before the daemon is
// registered: a root LaunchDaemon must never point into /Applications, which
// any admin can write to.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/spf13/cobra"
)

const (
	defaultServiceWorkingDirectory = "/Library/Application Support/sing-box-daemon"
	launchDaemonDirectory          = "/Library/LaunchDaemons"
	privilegedHelperDirectory      = "/Library/PrivilegedHelperTools"
	launchdServiceTarget           = "system/" + serviceName
	darwinSocketPath               = "/var/run/sing-box.socket"
)

func launchDaemonPlistPath() string {
	return filepath.Join(launchDaemonDirectory, serviceName+".plist")
}

func installedDaemonPath() string {
	return filepath.Join(privilegedHelperDirectory, serviceName)
}

var commandServiceInstall = &cobra.Command{
	Use:   "install",
	Short: "Install or update the system service",
	Args:  cobra.NoArgs,
	Run: func(command *cobra.Command, args []string) {
		err := serviceInstall()
		if err != nil {
			log.Fatal(E.Cause(err, "install service"))
		}
	},
}

var commandServiceUninstall = &cobra.Command{
	Use:   "uninstall",
	Short: "Uninstall the system service",
	Args:  cobra.NoArgs,
	Run: func(command *cobra.Command, args []string) {
		err := serviceUninstall()
		if err != nil {
			log.Fatal(E.Cause(err, "uninstall service"))
		}
	},
}

func addPlatformServiceCommands() {
	commandService.AddCommand(commandServiceInstall)
	commandService.AddCommand(commandServiceUninstall)
}

func requireRoot() error {
	if os.Geteuid() != 0 {
		return E.New("this command requires an elevated process")
	}
	return nil
}

func launchctl(arguments ...string) (string, error) {
	output, err := exec.Command("/bin/launchctl", arguments...).CombinedOutput()
	message := strings.TrimSpace(string(output))
	if err != nil {
		if message == "" {
			return "", E.Cause(err, "launchctl ", strings.Join(arguments, " "))
		}
		return "", E.New("launchctl ", strings.Join(arguments, " "), ": ", message)
	}
	return message, nil
}

/** The plist is written by us, so the escaping only has to survive our paths. */
func plistContent(executablePath string, workingDirectory string) string {
	escape := func(value string) string {
		value = strings.ReplaceAll(value, "&", "&amp;")
		value = strings.ReplaceAll(value, "<", "&lt;")
		return strings.ReplaceAll(value, ">", "&gt;")
	}
	arguments := []string{
		executablePath,
		"run",
		"--working-directory", workingDirectory,
		"--socket", darwinSocketPath,
	}
	var builder strings.Builder
	builder.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	builder.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	builder.WriteString(`<plist version="1.0">` + "\n<dict>\n")
	builder.WriteString("\t<key>Label</key>\n\t<string>" + serviceName + "</string>\n")
	builder.WriteString("\t<key>ProgramArguments</key>\n\t<array>\n")
	for _, argument := range arguments {
		builder.WriteString("\t\t<string>" + escape(argument) + "</string>\n")
	}
	builder.WriteString("\t</array>\n")
	builder.WriteString("\t<key>RunAtLoad</key>\n\t<true/>\n")
	builder.WriteString("\t<key>KeepAlive</key>\n\t<true/>\n")
	builder.WriteString("\t<key>ProcessType</key>\n\t<string>Interactive</string>\n")
	builder.WriteString("</dict>\n</plist>\n")
	return builder.String()
}

func writeRootOwnedFile(path string, content []byte, mode os.FileMode) error {
	err := os.WriteFile(path, content, mode)
	if err != nil {
		return err
	}
	err = os.Chown(path, 0, 0)
	if err != nil {
		return E.Cause(err, "set owner of ", path)
	}
	return os.Chmod(path, mode)
}

// The helper is what launchd executes as root, so it must live somewhere only
// root can write — not next to the application bundle.
func installPrivilegedHelper() (string, error) {
	sourcePath, err := os.Executable()
	if err != nil {
		return "", E.Cause(err, "get executable path")
	}
	sourcePath, err = filepath.EvalSymlinks(sourcePath)
	if err != nil {
		return "", E.Cause(err, "resolve executable path")
	}
	destinationPath := installedDaemonPath()
	if sourcePath == destinationPath {
		return destinationPath, nil
	}
	content, err := os.ReadFile(sourcePath)
	if err != nil {
		return "", E.Cause(err, "read daemon executable")
	}
	err = os.MkdirAll(privilegedHelperDirectory, 0o755)
	if err != nil {
		return "", E.Cause(err, "create ", privilegedHelperDirectory)
	}
	err = os.Chown(privilegedHelperDirectory, 0, 0)
	if err != nil {
		return "", E.Cause(err, "set owner of ", privilegedHelperDirectory)
	}
	// Replace rather than overwrite: the old binary may be running.
	_ = os.Remove(destinationPath)
	err = writeRootOwnedFile(destinationPath, content, 0o755)
	if err != nil {
		return "", E.Cause(err, "install daemon executable")
	}
	return destinationPath, nil
}

func ensureWorkingDirectory(path string) error {
	err := os.MkdirAll(path, 0o700)
	if err != nil {
		return E.Cause(err, "create working directory")
	}
	err = os.Chown(path, 0, 0)
	if err != nil {
		return E.Cause(err, "set owner of working directory")
	}
	return os.Chmod(path, 0o700)
}

func serviceInstall() error {
	err := requireRoot()
	if err != nil {
		return err
	}
	workingDirectory, err := filepath.Abs(commandServiceFlagWorkingDirectory)
	if err != nil {
		return E.Cause(err, "resolve working directory")
	}
	err = ensureWorkingDirectory(workingDirectory)
	if err != nil {
		return err
	}
	executablePath, err := installPrivilegedHelper()
	if err != nil {
		return err
	}
	// A previous registration would keep running the old plist.
	_, _ = launchctl("bootout", launchdServiceTarget)
	plistPath := launchDaemonPlistPath()
	err = writeRootOwnedFile(plistPath, []byte(plistContent(executablePath, workingDirectory)), 0o644)
	if err != nil {
		return E.Cause(err, "write launchd job")
	}
	_, err = launchctl("bootstrap", "system", plistPath)
	if err != nil {
		return err
	}
	_, err = launchctl("enable", launchdServiceTarget)
	if err != nil {
		return err
	}
	_, err = launchctl("kickstart", "-k", launchdServiceTarget)
	return err
}

func serviceUninstall() error {
	err := requireRoot()
	if err != nil {
		return err
	}
	_, _ = launchctl("bootout", launchdServiceTarget)
	err = os.Remove(launchDaemonPlistPath())
	if err != nil && !os.IsNotExist(err) {
		return E.Cause(err, "remove launchd job")
	}
	err = os.Remove(installedDaemonPath())
	if err != nil && !os.IsNotExist(err) {
		return E.Cause(err, "remove daemon executable")
	}
	return nil
}

func serviceInstalled() bool {
	_, err := os.Stat(launchDaemonPlistPath())
	return err == nil
}

func serviceStart() error {
	err := requireRoot()
	if err != nil {
		return err
	}
	if !serviceInstalled() {
		return E.New("service is not installed")
	}
	// bootstrap fails when the job is already loaded, which is fine here.
	_, _ = launchctl("bootstrap", "system", launchDaemonPlistPath())
	_, err = launchctl("enable", launchdServiceTarget)
	if err != nil {
		return err
	}
	_, err = launchctl("kickstart", launchdServiceTarget)
	return err
}

func serviceStop() error {
	err := requireRoot()
	if err != nil {
		return err
	}
	if !serviceInstalled() {
		return nil
	}
	_, err = launchctl("bootout", launchdServiceTarget)
	return err
}

func serviceStatus() (*serviceStatusResult, error) {
	if !serviceInstalled() {
		return &serviceStatusResult{exitCode: 3, description: "not installed"}, nil
	}
	output, err := launchctl("print", launchdServiceTarget)
	if err != nil {
		return &serviceStatusResult{exitCode: 3, description: "stopped"}, nil
	}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "state = ") {
			state := strings.TrimPrefix(line, "state = ")
			if state == "running" {
				return &serviceStatusResult{exitCode: 0, description: "running"}, nil
			}
			return &serviceStatusResult{exitCode: 3, description: state}, nil
		}
	}
	return &serviceStatusResult{exitCode: 3, description: "stopped"}, nil
}
