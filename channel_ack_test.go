package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Scripted-peer tests for waitChannelEarlyAck's early-ack semantics (M3):
// one absolute deadline, ≤2 identity-correlated retransmissions, and
// provisional/mismatched datagrams that carry no penalty. The window is
// injectable, so the tests run at 300 ms instead of the production 1.8 s
// (retransmit slots then land at 100 ms / 200 ms).

const testAckWindow = 300 * time.Millisecond

// ackScriptPeer is a scripted local UDP peer that records every datagram
// and delegates responses to a test-set callback (never responds on its
// own). Delayed replies are sent from the test via sendLater.
type ackScriptPeer struct {
	conn *net.UDPConn
	port int

	mu   sync.Mutex
	got  []string
	resp func(raw string, from *net.UDPAddr)
}

func newAckScriptPeer(t *testing.T) *ackScriptPeer {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Skipf("udp listen: %v", err)
	}
	p := &ackScriptPeer{conn: conn, port: conn.LocalAddr().(*net.UDPAddr).Port}
	go p.serve()
	t.Cleanup(func() { conn.Close() })
	return p
}

func (p *ackScriptPeer) serve() {
	buf := make([]byte, 65536)
	for {
		p.conn.SetReadDeadline(time.Now().Add(20 * time.Second))
		n, addr, err := p.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		raw := string(buf[:n])
		p.mu.Lock()
		p.got = append(p.got, raw)
		resp := p.resp
		p.mu.Unlock()
		if resp != nil {
			resp(raw, addr)
		}
	}
}

func (p *ackScriptPeer) setResp(fn func(raw string, from *net.UDPAddr)) {
	p.mu.Lock()
	p.resp = fn
	p.mu.Unlock()
}

// sendLater sends data to from after delay; run it in a goroutine so the
// peer's read loop stays free for retransmissions.
func (p *ackScriptPeer) sendLater(from *net.UDPAddr, delay time.Duration, data string) {
	if delay > 0 {
		time.Sleep(delay)
	}
	p.conn.WriteToUDP([]byte(data), from)
}

func (p *ackScriptPeer) requests() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.got...)
}

// channelRequests returns the recorded p2p-channel requests — one per send
// (initial + retransmissions), PTCP/noise excluded by the path filter.
func (p *ackScriptPeer) channelRequests() []string {
	var out []string
	for _, raw := range p.requests() {
		if strings.Contains(raw, "/p2p-channel") {
			out = append(out, raw)
		}
	}
	return out
}

// newAckTestSender binds a channel sender (dmss dialect, type 0 — identity
// correlation needs no auth) to a socket pointed at the scripted peer.
func newAckTestSender(t *testing.T, p *ackScriptPeer) (*UDP, *channelSender) {
	t.Helper()
	return newAckTestSenderProfile(t, p, dmssProfile)
}

// newAckTestSenderProfile is newAckTestSender for an arbitrary profile —
// used to exercise the no-pcs-id (smartpss) matching branch.
func newAckTestSenderProfile(t *testing.T, p *ackScriptPeer, prof *appProfile) (*UDP, *channelSender) {
	t.Helper()
	u := NewUDP("127.0.0.1", p.port, false, prof)
	t.Cleanup(u.Close)
	cs := newChannelSender(u, "SN123", prof, 0, "", "", "", u.lport, 80, []byte{1, 2, 3, 4, 5, 6, 7, 8})
	return u, cs
}

func noopLogf(string, ...any) {}

// capturingLogf collects log lines for assertions on the drop/terminal
// logging paths.
type capturingLogf struct {
	mu sync.Mutex
	it []string
}

func (c *capturingLogf) logf(format string, args ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.it = append(c.it, fmt.Sprintf(format, args...))
}

func (c *capturingLogf) lines() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.it...)
}

// (i) no response at all → exactly the 2 retransmits, then the absolute
// deadline — not a retransmit per read window (the old semantics stretched
// the same script to ~3× the window).
func TestWaitChannelEarlyAckRetransmitsThenDeadline(t *testing.T) {
	p := newAckScriptPeer(t) // never responds
	u, cs := newAckTestSender(t, p)

	cs.send(false)
	start := time.Now()
	early := waitChannelEarlyAck(u, cs, noopLogf, testAckWindow)
	elapsed := time.Since(start)

	if early != nil {
		t.Fatalf("silent peer returned %+v, want nil", early)
	}
	// The absolute window must be honored: well under the old per-read
	// behavior (~3 windows) but not returning before it either.
	if elapsed < testAckWindow/2 {
		t.Fatalf("returned after %v — did not wait out the window", elapsed)
	}
	if elapsed > testAckWindow+400*time.Millisecond {
		t.Fatalf("returned after %v — deadline not absolute", elapsed)
	}
	if n := len(p.channelRequests()); n != 3 {
		t.Fatalf("channel requests = %d, want 3 (initial + exactly 2 retransmits)", n)
	}
}

// (ii) 100 Trying then 200 → the final response is accepted, no retransmit
// is spent, and the 100 does not reset the deadline.
func TestWaitChannelEarlyAckTryingThenFinal(t *testing.T) {
	p := newAckScriptPeer(t)
	u, cs := newAckTestSender(t, p)

	var once sync.Once
	p.setResp(func(raw string, from *net.UDPAddr) {
		once.Do(func() {
			p.sendLater(from, 0, dhAck(raw, "100 Trying", ""))
			// Final before the first retransmit slot (window/3): a
			// provisional 100 must trigger no retransmit at all.
			p.sendLater(from, testAckWindow/4, dhAck(raw, "200 OK", "<body><PubAddr>127.0.0.1:25024</PubAddr></body>"))
		})
	})

	cs.send(false)
	start := time.Now()
	early := waitChannelEarlyAck(u, cs, noopLogf, testAckWindow)
	elapsed := time.Since(start)

	if early == nil || early.Code != 200 {
		t.Fatalf("early ack = %v, want the 200 OK", early)
	}
	if early.Body["body/PubAddr"] != "127.0.0.1:25024" {
		t.Fatalf("wrong response accepted: %v", early.Body)
	}
	if elapsed >= testAckWindow {
		t.Fatalf("returned after %v — the 100 Trying reset the deadline", elapsed)
	}
	if n := len(p.channelRequests()); n != 1 {
		t.Fatalf("channel requests = %d, want 1 (no retransmit after the 100)", n)
	}
}

// (iii) with a pcs-id on the request, a VALID 200 answering under the right
// pcs-id but a foreign CSeq is ACCEPTED — the cloud sometimes emits `CSeq: 0`
// on valid responses (live 2026-09-06), so CSeq is not a matching criterion
// when a pcs-id exists. A foreign-pcs-id 200 and a garbage datagram are
// dropped, each with a logged classification.
func TestWaitChannelEarlyAckPcsIDAloneMatching(t *testing.T) {
	p := newAckScriptPeer(t)
	u, cs := newAckTestSender(t, p)
	logs := &capturingLogf{}

	var once sync.Once
	p.setResp(func(raw string, from *net.UDPAddr) {
		once.Do(func() {
			// Wrong x-pcs-request-id (CSeq right): dropped.
			wrongPcs := strings.Replace(dhAck(raw, "200 OK", "<body><PubAddr>9.9.9.8:8</PubAddr></body>"),
				cs.req.pcsID, "ffffffffffffffffffffffffffffffff", 1)
			// All before the first retransmit slot (window/3): strangers
			// must be dropped without spending a retransmit.
			p.sendLater(from, 0, wrongPcs)
			p.sendLater(from, 0, "not a DH response at all")
			p.sendLater(from, testAckWindow/4, dhAck(raw, "200 OK", "<body><PubAddr>127.0.0.1:25024</PubAddr></body>"))
		})
	})

	cs.send(false)
	early := waitChannelEarlyAck(u, cs, logs.logf, testAckWindow)

	if early == nil || early.Code != 200 || early.Body["body/PubAddr"] != "127.0.0.1:25024" {
		t.Fatalf("early ack = %v, want the pcs-matched 200 OK (not the strangers)", early)
	}
	if n := len(p.channelRequests()); n != 1 {
		t.Fatalf("channel requests = %d, want 1 (mismatched datagrams must not consume the budget)", n)
	}
	// Drop-logging path: every dropped datagram is logged with its class —
	// the parseable stranger by status line, the garbage by fingerprint.
	lines := logs.lines()
	var pcsDrops, garbageDrops int
	for _, l := range lines {
		if strings.Contains(l, "dropping datagram") && strings.Contains(l, `status line "HTTP/1.1 200 OK"`) {
			pcsDrops++
		}
		if strings.Contains(l, "dropping datagram") && strings.Contains(l, `unparseable "not a DH response at all"`) {
			garbageDrops++
		}
	}
	if pcsDrops != 1 || garbageDrops != 1 {
		t.Fatalf("drop logs: pcs-id drops=%d garbage drops=%d, want 1/1:\n%s",
			pcsDrops, garbageDrops, strings.Join(lines, "\n"))
	}
}

// (iii-b) the live `CSeq: 0` shape: 100 Trying and the final 200 both echo
// the request's pcs-id but carry CSeq: 0 — both must be accepted (the 100
// as provisional, the 200 as the outcome), no retransmit spent.
func TestWaitChannelEarlyAckAcceptsCSeqZero(t *testing.T) {
	p := newAckScriptPeer(t)
	u, cs := newAckTestSender(t, p)

	var once sync.Once
	p.setResp(func(raw string, from *net.UDPAddr) {
		once.Do(func() {
			cseqZero := func(status, body string) string {
				return strings.Replace(dhAck(raw, status, body),
					"CSeq: "+strconv.FormatUint(uint64(cs.req.cseq), 10), "CSeq: 0", 1)
			}
			p.sendLater(from, 0, cseqZero("100 Trying", ""))
			p.sendLater(from, testAckWindow/4, cseqZero("200 OK", "<body><PubAddr>127.0.0.1:25024</PubAddr></body>"))
		})
	})

	cs.send(false)
	early := waitChannelEarlyAck(u, cs, noopLogf, testAckWindow)

	if early == nil || early.Code != 200 || early.Body["body/PubAddr"] != "127.0.0.1:25024" {
		t.Fatalf("early ack = %v, want the CSeq:0 200 OK accepted on pcs-id alone", early)
	}
	if n := len(p.channelRequests()); n != 1 {
		t.Fatalf("channel requests = %d, want 1 (CSeq:0 responses must not trigger retransmits)", n)
	}
}

// (iii-c) any 4xx/5xx final response is TERMINAL regardless of identity —
// the live 403 carries a server-GENERATED x-pcs-request-id (never an echo),
// so it can never correlate; it must surface with its status line instead
// of starving the wait.
func TestWaitChannelEarlyAckErrorIsTerminal(t *testing.T) {
	p := newAckScriptPeer(t)
	u, cs := newAckTestSender(t, p)
	logs := &capturingLogf{}

	var once sync.Once
	p.setResp(func(raw string, from *net.UDPAddr) {
		once.Do(func() {
			// The live 403 shape: echoed CSeq replaced too — terminal must
			// not depend on any identity match.
			err403 := strings.Replace(dhAck(raw, "403 DevPwd_InvalidDigest", "<body></body>"),
				"CSeq: "+strconv.FormatUint(uint64(cs.req.cseq), 10), "CSeq: 9999", 1)
			err403 = strings.Replace(err403, cs.req.pcsID, "ffffffffffffffffffffffffffffffff", 1)
			p.sendLater(from, 0, err403)
		})
	})

	cs.send(false)
	start := time.Now()
	early := waitChannelEarlyAck(u, cs, logs.logf, testAckWindow)

	if early == nil || early.Code != 403 || early.Status != "DevPwd_InvalidDigest" {
		t.Fatalf("early ack = %v, want the terminal 403 DevPwd_InvalidDigest", early)
	}
	if elapsed := time.Since(start); elapsed > 150*time.Millisecond {
		t.Fatalf("terminal 403 took %v to surface — not immediate", elapsed)
	}
	if n := len(p.channelRequests()); n != 1 {
		t.Fatalf("channel requests = %d, want 1 (no retransmit after a terminal error)", n)
	}
	terminalLogged := false
	for _, l := range logs.lines() {
		if strings.Contains(l, "terminal 403") {
			terminalLogged = true
		}
	}
	if !terminalLogged {
		t.Fatalf("terminal error not logged:\n%s", strings.Join(logs.lines(), "\n"))
	}
}

// (iii-d) requests WITHOUT a pcs-id keep CSeq matching: a 200 under a
// foreign CSeq is dropped (logged), the CSeq-matched 200 is accepted.
func TestWaitChannelEarlyAckCSeqMatchingWithoutPcsID(t *testing.T) {
	p := newAckScriptPeer(t)
	u, cs := newAckTestSenderProfile(t, p, smartpssProfile) // pcsRequestID=false → no pcs-id
	if cs.req.pcsID != "" {
		t.Fatalf("smartpss channel request carries pcs-id %q", cs.req.pcsID)
	}
	logs := &capturingLogf{}

	var once sync.Once
	p.setResp(func(raw string, from *net.UDPAddr) {
		once.Do(func() {
			wrongCSeq := strings.Replace(dhAck(raw, "200 OK", "<body><PubAddr>9.9.9.9:9</PubAddr></body>"),
				"CSeq: "+strconv.FormatUint(uint64(cs.req.cseq), 10), "CSeq: 9999", 1)
			p.sendLater(from, 0, wrongCSeq)
			p.sendLater(from, testAckWindow/4, dhAck(raw, "200 OK", "<body><PubAddr>127.0.0.1:25024</PubAddr></body>"))
		})
	})

	cs.send(false)
	early := waitChannelEarlyAck(u, cs, logs.logf, testAckWindow)

	if early == nil || early.Code != 200 || early.Body["body/PubAddr"] != "127.0.0.1:25024" {
		t.Fatalf("early ack = %v, want the CSeq-matched 200 OK (not the stranger)", early)
	}
	if n := len(p.channelRequests()); n != 1 {
		t.Fatalf("channel requests = %d, want 1 (the stranger must not consume the budget)", n)
	}
	dropLogged := false
	for _, l := range logs.lines() {
		if strings.Contains(l, "dropping datagram") && strings.Contains(l, `CSeq "9999"`) {
			dropLogged = true
		}
	}
	if !dropLogged {
		t.Fatalf("CSeq-mismatch drop not logged:\n%s", strings.Join(logs.lines(), "\n"))
	}
}

// (iv) a 200 with matching CSeq and pcsID is accepted immediately — no
// retransmit, no waiting out the window.
func TestWaitChannelEarlyAcceptsMatchedFinal(t *testing.T) {
	p := newAckScriptPeer(t)
	u, cs := newAckTestSender(t, p)

	var once sync.Once
	p.setResp(func(raw string, from *net.UDPAddr) {
		once.Do(func() {
			p.sendLater(from, 0, dhAck(raw, "200 OK", "<body><PubAddr>127.0.0.1:25024</PubAddr></body>"))
		})
	})

	cs.send(false)
	start := time.Now()
	early := waitChannelEarlyAck(u, cs, noopLogf, testAckWindow)

	if early == nil || early.Code != 200 {
		t.Fatalf("early ack = %v, want the 200 OK", early)
	}
	if elapsed := time.Since(start); elapsed > 150*time.Millisecond {
		t.Fatalf("matched 200 took %v to accept — not immediate", elapsed)
	}
	if n := len(p.channelRequests()); n != 1 {
		t.Fatalf("channel requests = %d, want 1", n)
	}
}
