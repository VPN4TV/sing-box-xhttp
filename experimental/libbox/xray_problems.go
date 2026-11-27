package libbox

import (
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	xrayapplog "github.com/xtls/xray-core/app/log"
	xraylog "github.com/xtls/xray-core/common/log"
	xraycore "github.com/xtls/xray-core/core"
)

// VPN4TV: the xray bridge's own warnings and errors, kept for "Send to
// support" (with the info lines of a failure, see kept). Xray writes its log to stdout, which on Android goes to logcat at
// best: a customer's report had none of it. Case of 2026-11-26 (a SaluteTV,
// Android 9): every connection to the bridge's port timed out, and nothing
// told whether xray had stopped taking connections or never got them.
// The newest xrayProblemsKept lines, a repeat of the line before counted
// instead of kept. They go out as xray wrote them; the app takes names and
// addresses out before a report leaves the device.

const xrayProblemsKept = 40

type xrayProblemLog struct {
	access sync.Mutex
	lines  []xrayProblem
	next   xraylog.Handler
}

type xrayProblem struct {
	at      time.Time // the first time
	last    time.Time // the last repeat
	text    string
	repeats int
}

var xrayProblems = &xrayProblemLog{}

func (l *xrayProblemLog) Handle(msg xraylog.Message) {
	if general, isGeneral := msg.(*xraylog.GeneralMessage); isGeneral && kept(general) {
		l.add(time.Now(), general.String())
	}
	l.access.Lock()
	next := l.next
	l.access.Unlock()
	if next != nil {
		next.Handle(msg)
	}
}

// kept: warnings and errors, and the info lines of a failure; xray writes a
// connection it could not carry ("failed to process outbound traffic > … dial
// tcp …: i/o timeout") at info.
func kept(message *xraylog.GeneralMessage) bool {
	switch message.Severity {
	case xraylog.Severity_Error, xraylog.Severity_Warning:
		return true
	case xraylog.Severity_Info:
		return strings.Contains(strings.ToLower(message.String()), "failed")
	default:
		return false
	}
}

// connectionID: the number xray gives each connection ("[Info] [90169671] …"):
// without it the same failure of every connection is one line.
var connectionID = regexp.MustCompile(`^(\[[A-Za-z]+\]) \[\d+\] `)

func (l *xrayProblemLog) add(at time.Time, text string) {
	text = strings.ReplaceAll(strings.TrimSpace(text), "\n", " ")
	text = connectionID.ReplaceAllString(text, "$1 ")
	if len(text) > 600 {
		text = text[:600] + "…"
	}
	l.access.Lock()
	defer l.access.Unlock()
	if n := len(l.lines); n > 0 && l.lines[n-1].text == text {
		l.lines[n-1].repeats++
		l.lines[n-1].last = at
		return
	}
	l.lines = append(l.lines, xrayProblem{at: at, text: text})
	if len(l.lines) > xrayProblemsKept {
		l.lines = append(l.lines[:0], l.lines[len(l.lines)-xrayProblemsKept:]...)
	}
}

// chain puts the log in front of the instance's own handler, which xray's log
// app registered when the instance was made, so xray's own output goes on as
// it was.
func (l *xrayProblemLog) chain(instance *xraycore.Instance) {
	own, _ := instance.GetFeature((*xrayapplog.Instance)(nil)).(*xrayapplog.Instance)
	l.access.Lock()
	if own != nil {
		l.next = own
	} else {
		l.next = nil
	}
	l.access.Unlock()
	xraylog.RegisterHandler(l)
}

func (l *xrayProblemLog) text() string {
	l.access.Lock()
	defer l.access.Unlock()
	var b strings.Builder
	for _, line := range l.lines {
		b.WriteString(line.at.Format("15:04:05"))
		b.WriteString(" ")
		b.WriteString(line.text)
		if line.repeats > 0 {
			b.WriteString(" (and ")
			b.WriteString(strconv.Itoa(line.repeats))
			b.WriteString(" more times, the last at ")
			b.WriteString(line.last.Format("15:04:05"))
			b.WriteString(")")
		}
		b.WriteString("\n")
	}
	return b.String()
}

func (l *xrayProblemLog) clear() {
	l.access.Lock()
	l.lines = nil
	l.access.Unlock()
}

// XrayProblems: the bridge's newest warnings and errors since its last start,
// a line each, oldest first; empty when there were none.
func XrayProblems() string {
	return xrayProblems.text()
}
