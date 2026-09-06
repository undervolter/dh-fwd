package main

import (
	"bytes"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Best-effort relay-agent allocation for relayAgentOptional profiles (dmss).
// Live 2026-09-06: the Dolynk relay dispatcher handed out by /online/relay
// was DEAD — /relay/agent answered with silence (17 s × 3) — and upstream's
// unconditional allocation blocked every tunnel attempt into a restart loop.
// The DMSS app never allocates the agent (zero /online/relay, /relay/agent
// and relay-channel traffic in both captures): its data path is the punched
// direct channel over the main cloud (Policy p2p,udprelay). These tests pin
// the profile-gated fix on scripted peers:
//
//	(a) dmss: dispatcher known but the agent leg a silent UDP black hole →
//	    one bounded probe, the whole agent stage skipped, [OK] on the direct
//	    channel, and the required "proceeding without" log line;
//	(b) smartpss: the same silent agent stays FATAL (upstream semantics);
//	(c) dmss: even the /online/relay lookup itself silent → no agent probe
//	    at all, same [OK];
//	(d) smartpss: a silent /online/relay stays FATAL too.

// captureStdout runs fn with os.Stdout redirected into a pipe and returns
// everything printed during fn (t.logf → fmt.Println when no UI is attached).
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	done := make(chan string)
	go func() {
		buf := new(bytes.Buffer)
		_, _ = io.Copy(buf, r)
		done <- buf.String()
	}()
	fn()
	os.Stdout = orig
	w.Close()
	out := <-done
	r.Close()
	return out
}

// newAgentTestTunnel builds a dmss Type-1 tunnel pointed at the scripted peer
// the way runMulti wires it after a successful preflight (explicit salt) and
// shrinks the best-effort dispatcher timeouts so the black-hole probes cost
// milliseconds, not seconds. The local-channel step is disabled: it fires on
// a background goroutine and its debug logging would race captureStdout's
// os.Stdout restore (the step's own wire form and snapshot semantics are
// covered by the TestSendLocalChannel* tests).
func newAgentTestTunnel(t *testing.T, p *dhTestPeer, debug bool) *Tunnel {
	t.Helper()
	prof := newTestPeerProfile(p)
	prof.localChannel = false

	origLookup, origAgent := relayLookupTimeout, relayAgentTimeout
	relayLookupTimeout, relayAgentTimeout = 300*time.Millisecond, 300*time.Millisecond
	t.Cleanup(func() { relayLookupTimeout, relayAgentTimeout = origLookup, origAgent })

	g := specGroup{idxs: []int{0}, specs: []PortSpec{{Local: 0, Remote: 554}}}
	tt := newTunnel("SN123", prof, 1, "admin", "pw", testSalt, debug, false, false, 0, g, nil)
	t.Cleanup(tt.close)
	return tt
}

// answerDirectPath arms the scripted peer for a full dmss establishment on
// the punched direct channel while keeping silent every request the
// blackHole predicate names (a UDP black hole, like the dead Dolynk
// dispatcher). Everything else falls through to defaultRespond: the relay
// lookup hands out the peer itself as the dispatcher address, the Info blob
// carries the test salt, unmatched requests get the catch-all 200.
func answerDirectPath(p *dhTestPeer, blackHole func(raw string) bool) {
	p.setRespFn(func(raw string) (string, bool) {
		switch {
		case blackHole(raw):
			return "", true // silent — the datagram is lost
		case strings.HasPrefix(raw, "NFPOST /device/SN123/p2p-channel"):
			// PubAddr AND LocalAddr point at the peer so both the STUN
			// punch targets reach the scripted responder (no dead port,
			// no ICMP noise on the punch socket).
			return dhAck(raw, "200 OK",
				"<body><PubAddr>127.0.0.1:"+strconv.Itoa(p.port)+"</PubAddr>"+
					"<LocalAddr>127.0.0.1:"+strconv.Itoa(p.port)+"</LocalAddr>"+
					"<Policy>p2p,udprelay</Policy></body>"), true
		case strings.HasPrefix(raw, "PTCP"):
			if len(raw) >= 25 {
				body := raw[24:]
				if len(body) == 4 && body[0] == 0x00 && body[1] == 0x03 && body[2] == 0x01 && body[3] == 0x00 {
					return ptcpReply([]byte{0x00, 0x03, 0x01, 0x00}), true // sync echo
				}
			}
			return "", true // other frames: stay silent
		case len(raw) >= 4 && raw[0] == '\xff' && raw[1] == '\xfe' && raw[2] == '\xff' && raw[3] == '\xe7':
			return string([]byte{0xfe, 0xfe, 0xff, 0xe7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}), true
		}
		return "", false // defaultRespond (p2psrv, info, relay lookup, …)
	})
}

// agentStageRequests counts the relay-agent stage's wire evidence.
func agentStageRequests(t *testing.T, p *dhTestPeer) (agent, start, relayCh int) {
	t.Helper()
	for _, raw := range dhRequests(p) {
		switch {
		case strings.Contains(raw, "/relay/agent"):
			agent++
		case strings.Contains(raw, "/relay/start/"):
			start++
		case strings.Contains(raw, "/relay-channel"):
			relayCh++
		}
	}
	return agent, start, relayCh
}

// (a) dmss: /online/relay answers (the dispatcher address is handed out) but
// the agent leg is a silent UDP black hole — exactly the live Dolynk failure.
// The handshake must cost only ONE bounded probe (not a 15 s read, not a
// restart loop), skip the whole agent stage (no /relay/start, no
// relay-channel, no PTCP sync over a dead agent), log the required
// "proceeding without" line, and establish [OK] on the punched direct
// channel.
func TestHandshakeDMSSProceedsWhenAgentBlackHole(t *testing.T) {
	p := newDHTestPeer(t)
	tt := newAgentTestTunnel(t, p, true) // debug: the failure must be logged
	answerDirectPath(p, func(raw string) bool { return strings.Contains(raw, "/relay/agent") })

	var hsErr error
	start := time.Now()
	out := captureStdout(t, func() {
		hsErr = tt.handshake()
	})
	if hsErr != nil {
		t.Fatalf("handshake failed despite the best-effort agent allocation: %v", hsErr)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("handshake took %v — the dead dispatcher must cost one bounded probe, not RELAY_READ_TIMEOUT", elapsed)
	}
	if tt.primary != tt.deviceRemote {
		t.Fatal("data path is not the punched direct channel (deviceRemote)")
	}

	agent, relayStart, relayCh := agentStageRequests(t, p)
	if agent != 1 {
		t.Fatalf("/relay/agent requests = %d, want exactly 1 (one bounded best-effort probe)", agent)
	}
	if relayStart != 0 || relayCh != 0 {
		t.Fatalf("agent stage not skipped: /relay/start=%d relay-channel=%d", relayStart, relayCh)
	}

	const wantLog = "relay dispatcher unavailable — proceeding without TCP relay agent (app-parity: DMSS never uses it)"
	if !strings.Contains(out, wantLog) {
		t.Fatalf("failure not logged as required.\ngot:\n%s", out)
	}
}

// (b) smartpss: upstream semantics pinned — a silent agent endpoint stays
// FATAL (the allocation is mandatory) and nothing after it hits the wire.
func TestHandshakeSmartPSSAgentStillFatalWhenSilent(t *testing.T) {
	p := newDHTestPeer(t)
	prof := *smartpssProfile
	prof.mainServer = "127.0.0.1"
	prof.mainPort = p.port

	orig := RELAY_READ_TIMEOUT
	RELAY_READ_TIMEOUT = 250 * time.Millisecond
	defer func() { RELAY_READ_TIMEOUT = orig }()

	g := specGroup{idxs: []int{0}, specs: []PortSpec{{Local: 0, Remote: 554}}}
	tt := newTunnel("SN123", &prof, 0, "", "", "", false, false, false, 0, g, nil)
	defer tt.close()

	answerDirectPath(p, func(raw string) bool { return strings.Contains(raw, "/relay/agent") })

	err := tt.handshake()
	if err == nil {
		t.Fatal("smartpss handshake succeeded with a silent agent endpoint — the mandatory stage regressed to best-effort")
	}
	if !strings.Contains(err.Error(), "relay agent") {
		t.Fatalf("error = %v, want the relay-agent stage failure", err)
	}
	if _, relayStart, relayCh := agentStageRequests(t, p); relayStart != 0 || relayCh != 0 {
		t.Fatalf("requests emitted after the failed agent allocation: /relay/start=%d relay-channel=%d", relayStart, relayCh)
	}
}

// (c) dmss: even the /online/relay lookup itself can hang — also best-effort.
// With the whole dispatcher exchange silent, no /relay/agent probe goes out
// at all and the handshake still establishes [OK] on the direct channel.
func TestHandshakeDMSSProceedsWhenDispatcherBlackHole(t *testing.T) {
	p := newDHTestPeer(t)
	tt := newAgentTestTunnel(t, p, true)
	answerDirectPath(p, func(raw string) bool { return strings.Contains(raw, "/online/relay") })

	var hsErr error
	start := time.Now()
	out := captureStdout(t, func() {
		hsErr = tt.handshake()
	})
	if hsErr != nil {
		t.Fatalf("handshake failed despite the skipped dispatcher exchange: %v", hsErr)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("handshake took %v — the silent lookup must cost one bounded probe", elapsed)
	}
	if tt.primary != tt.deviceRemote {
		t.Fatal("data path is not the punched direct channel (deviceRemote)")
	}

	if agent, relayStart, relayCh := agentStageRequests(t, p); agent != 0 || relayStart != 0 || relayCh != 0 {
		t.Fatalf("agent stage must be skipped entirely: /relay/agent=%d /relay/start=%d relay-channel=%d",
			agent, relayStart, relayCh)
	}

	const wantLog = "relay dispatcher lookup failed"
	if !strings.Contains(out, wantLog) {
		t.Fatalf("lookup failure not logged.\ngot:\n%s", out)
	}
}

// (d) smartpss: a silent /online/relay stays FATAL (upstream semantics) —
// the dispatcher lookup is mandatory for the smartpss profile.
func TestHandshakeSmartPSSDispatcherStillFatalWhenSilent(t *testing.T) {
	p := newDHTestPeer(t)
	prof := *smartpssProfile
	prof.mainServer = "127.0.0.1"
	prof.mainPort = p.port

	orig := RELAY_READ_TIMEOUT
	RELAY_READ_TIMEOUT = 250 * time.Millisecond
	defer func() { RELAY_READ_TIMEOUT = orig }()

	g := specGroup{idxs: []int{0}, specs: []PortSpec{{Local: 0, Remote: 554}}}
	tt := newTunnel("SN123", &prof, 0, "", "", "", false, false, false, 0, g, nil)
	defer tt.close()

	answerDirectPath(p, func(raw string) bool { return strings.Contains(raw, "/online/relay") })

	err := tt.handshake()
	if err == nil {
		t.Fatal("smartpss handshake succeeded with a silent dispatcher lookup — the mandatory stage regressed to best-effort")
	}
	if !strings.Contains(err.Error(), "relay lookup") {
		t.Fatalf("error = %v, want the relay-lookup stage failure", err)
	}
	if agent, _, _ := agentStageRequests(t, p); agent != 0 {
		t.Fatalf("/relay/agent probes = %d, want 0 (fatal before the agent stage)", agent)
	}
}
