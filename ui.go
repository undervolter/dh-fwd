package main

import (
	"fmt"
	"io"
	"strings"
	"sync"
)

type uiCmd int

const (
	uiCmdInit uiCmd = iota
	uiCmdUpdate
	uiCmdBelow
)

type uiMsg struct {
	cmd  uiCmd
	idx  int
	text string
}

// UI serializes console output for multi-tunnel mode: all lines go through
// one writer goroutine so parallel tunnels never interleave mid-line.
type UI struct {
	ch chan uiMsg
	w  io.Writer
}

func NewUI(w io.Writer) *UI {
	u := &UI{
		ch: make(chan uiMsg, 256),
		w:  w,
	}
	go u.run()
	return u
}

func (u *UI) Start(header string, n int) {
	u.ch <- uiMsg{cmd: uiCmdInit, text: header}
}

func (u *UI) Update(idx int, line string) {
	u.ch <- uiMsg{cmd: uiCmdUpdate, idx: idx, text: line}
}

func (u *UI) Below(text string) {
	u.ch <- uiMsg{cmd: uiCmdBelow, text: text}
}

func (u *UI) run() {
	for m := range u.ch {
		switch m.cmd {
		case uiCmdInit, uiCmdUpdate, uiCmdBelow:
			fmt.Fprintln(u.w, m.text)
		}
	}
}

// ---------------------------------------------------------------------------
// ConnectProgress: in-place progress line for single-tunnel mode.
// Renders a bar + status that overwrites itself on the same terminal line.
// ---------------------------------------------------------------------------

const cpBarWidth = 24

// cpPhaseNames maps numeric phase constants to human-readable labels.
// Weights must sum to cpBarWidth (24).
var cpPhaseWeights = [cpPhaseCount]int{4, 2, 3, 4, 3, 4, 4}
var cpPhaseLabels = [cpPhaseCount]string{
	"cloud lookup",
	"device probe",
	"relay alloc",
	"p2p-channel",
	"relay-channel",
	"NAT punch",
	"PTCP handshake",
}

const (
	PhaseCloudLookup    = 0
	PhaseDeviceProbe    = 1
	PhaseRelayAlloc     = 2
	PhaseP2PChannel     = 3
	PhaseRelayChannel   = 4
	PhaseNATPunch       = 5
	PhasePTCPHandshake  = 6
	cpPhaseCount        = 7
)

// ConnectProgress renders a single updating line:
//
//	Connecting to SN:80 [=============>          ] 55% | relay alloc
type ConnectProgress struct {
	mu      sync.Mutex
	w       io.Writer
	target  string
	phase   int
	status  string
	filled  int
	attempt int
}

func NewConnectProgress(w io.Writer, target string) *ConnectProgress {
	cp := &ConnectProgress{
		w:      w,
		target: target,
	}
	cp.render()
	return cp
}

// SetAttempt updates the attempt counter shown in the bar (when > 1).
func (cp *ConnectProgress) SetAttempt(n int) {
	cp.mu.Lock()
	cp.attempt = n
	cp.mu.Unlock()
	cp.render()
}

// Reset resets the bar to 0% with a given status — call before a retry.
func (cp *ConnectProgress) Reset(status string) {
	cp.mu.Lock()
	cp.phase = 0
	cp.filled = 0
	cp.status = status
	cp.mu.Unlock()
	cp.render()
}

// Phase advances to the given phase index and re-renders.
func (cp *ConnectProgress) Phase(phase int, status string) {
	cp.mu.Lock()
	if phase > cp.phase {
		cp.phase = phase
	}
	if status != "" {
		cp.status = status
	} else if phase < cpPhaseCount {
		cp.status = cpPhaseLabels[phase]
	}
	// Recompute filled cells: sum of weights for completed phases + half of current.
	filled := 0
	for i := 0; i < phase && i < cpPhaseCount; i++ {
		filled += cpPhaseWeights[i]
	}
	if phase < cpPhaseCount {
		filled += cpPhaseWeights[phase] / 2
	}
	if filled > cpBarWidth {
		filled = cpBarWidth
	}
	cp.filled = filled
	cp.mu.Unlock()
	cp.render()
}

// Done marks progress as complete and prints a trailing newline.
func (cp *ConnectProgress) Done(finalMsg string) {
	cp.mu.Lock()
	cp.filled = cpBarWidth
	cp.status = finalMsg
	cp.mu.Unlock()
	cp.render()
	fmt.Fprintln(cp.w)
}

// Fail prints the failure reason and a trailing newline.
func (cp *ConnectProgress) Fail(reason string) {
	cp.mu.Lock()
	cp.status = "failed: " + reason
	cp.mu.Unlock()
	cp.render()
	fmt.Fprintln(cp.w)
}

func (cp *ConnectProgress) render() {
	cp.mu.Lock()
	filled := cp.filled
	status := cp.status
	attempt := cp.attempt
	target := cp.target
	cp.mu.Unlock()

	pct := 0
	var bar string
	if filled >= cpBarWidth {
		bar = strings.Repeat("=", cpBarWidth-1) + ">"
		pct = 100
	} else {
		spaces := cpBarWidth - 1 - filled
		if spaces < 0 {
			spaces = 0
		}
		bar = strings.Repeat("=", filled) + ">" + strings.Repeat(" ", spaces)
		pct = filled * 100 / cpBarWidth
	}

	attemptStr := ""
	if attempt > 1 {
		attemptStr = fmt.Sprintf(" [retry %d/%d]", attempt, RETRY_ATTEMPTS)
	}

	line := fmt.Sprintf("Connecting to %s%s [%s] %3d %% | %s",
		target, attemptStr, bar, pct, status)
	if len(line) < 110 {
		line += strings.Repeat(" ", 110-len(line))
	}
	fmt.Fprintf(cp.w, "\r%s", line)
}

// ---------------------------------------------------------------------------
// ScanProgress: in-place progress line for port scanning.
// Renders: Scanning SN [=========>             ] 45 % | port 37777 (5/15)
// ---------------------------------------------------------------------------

type ScanProgress struct {
	mu      sync.Mutex
	w       io.Writer
	serial  string
	total   int
	done    int
	current string
}

func NewScanProgress(w io.Writer, serial string, total int) *ScanProgress {
	sp := &ScanProgress{
		w:      w,
		serial: serial,
		total:  total,
	}
	sp.render()
	return sp
}

func (sp *ScanProgress) UpdateScanning(doneIdx int, currentPort int) {
	sp.mu.Lock()
	sp.done = doneIdx
	sp.current = fmt.Sprintf("port %d (%d/%d)", currentPort, doneIdx+1, sp.total)
	sp.mu.Unlock()
	sp.render()
}

func (sp *ScanProgress) UpdateWaiting(doneCount int, lastPort int, state string, secondsLeft int) {
	sp.mu.Lock()
	sp.done = doneCount
	sp.current = fmt.Sprintf("port %d (%s) — wait %ds...", lastPort, state, secondsLeft)
	sp.mu.Unlock()
	sp.render()
}

func (sp *ScanProgress) Update(done int, currentPort int) {
	sp.mu.Lock()
	sp.done = done
	if currentPort > 0 {
		sp.current = fmt.Sprintf("port %d (%d/%d)", currentPort, done, sp.total)
	} else {
		sp.current = fmt.Sprintf("(%d/%d)", done, sp.total)
	}
	sp.mu.Unlock()
	sp.render()
}

func (sp *ScanProgress) Done() {
	sp.mu.Lock()
	sp.done = sp.total
	sp.current = "scan complete"
	sp.mu.Unlock()
	sp.render()
	fmt.Fprintln(sp.w)
}

func (sp *ScanProgress) render() {
	sp.mu.Lock()
	done := sp.done
	total := sp.total
	serial := sp.serial
	curr := sp.current
	sp.mu.Unlock()

	pct := 0
	if total > 0 {
		pct = done * 100 / total
	}
	if pct > 100 {
		pct = 100
	}

	filled := 0
	if total > 0 {
		filled = done * cpBarWidth / total
	}
	if filled > cpBarWidth {
		filled = cpBarWidth
	}

	var bar string
	if filled >= cpBarWidth {
		bar = strings.Repeat("=", cpBarWidth-1) + ">"
	} else {
		spaces := cpBarWidth - 1 - filled
		if spaces < 0 {
			spaces = 0
		}
		bar = strings.Repeat("=", filled) + ">" + strings.Repeat(" ", spaces)
	}

	line := fmt.Sprintf("Scanning %s [%s] %3d %% | %s", serial, bar, pct, curr)
	if len(line) < 110 {
		line += strings.Repeat(" ", 110-len(line))
	}
	fmt.Fprintf(sp.w, "\r%s", line)
}

