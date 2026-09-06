package main

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Scripted-peer tests for the multi-mode preflight (verifyDevice) and the
// request sequences it shares with the tunnel handshake. The peer answers
// every DH request with a canned response chosen by path and records every
// datagram, so assertions run on the actual wire forms.

const testSalt = "TSTSA1T"

// dhTestPeer is a scripted local UDP peer. respFn, when set, inspects each
// raw datagram first: (response, true) overrides the default dispatcher —
// an empty response with true keeps the peer deliberately silent (lost
// datagram); (any, false) falls through to defaultRespond.
type dhTestPeer struct {
	conn   *net.UDPConn
	port   int
	mu     sync.Mutex
	got    []string
	respFn func(raw string) (resp string, handled bool)
}

func newDHTestPeer(t *testing.T) *dhTestPeer {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Skipf("udp listen: %v", err)
	}
	p := &dhTestPeer{conn: conn, port: conn.LocalAddr().(*net.UDPAddr).Port}
	go p.serve()
	t.Cleanup(func() { p.conn.Close() })
	return p
}

func (p *dhTestPeer) requests() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.got...)
}

// setRespFn installs respFn under the peer mutex — serve reads it from
// another goroutine, so a direct assignment would be a data race.
func (p *dhTestPeer) setRespFn(fn func(raw string) (resp string, handled bool)) {
	p.mu.Lock()
	p.respFn = fn
	p.mu.Unlock()
}

func (p *dhTestPeer) serve() {
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
		fn := p.respFn
		p.mu.Unlock()

		if fn != nil {
			if resp, handled := fn(raw); handled {
				if resp != "" {
					p.conn.WriteToUDP([]byte(resp), addr)
				}
				continue
			}
		}
		if resp := p.defaultRespond(raw); resp != "" {
			p.conn.WriteToUDP([]byte(resp), addr)
		}
	}
}

// echoIdentity renders the CSeq / x-pcs-request-id header lines echoing a
// captured request — a device answers a DH request under its identity.
func echoIdentity(raw string) string {
	var b strings.Builder
	if m := cseqRe.FindStringSubmatch(raw); m != nil {
		b.WriteString("CSeq: " + m[1] + "\r\n")
	}
	if m := regexp.MustCompile(`(?i)x-pcs-request-id: ([0-9a-f]+)\r\n`).FindStringSubmatch(raw); m != nil {
		b.WriteString("x-pcs-request-id: " + m[1] + "\r\n")
	}
	return b.String()
}

// dhAck builds a DH response for raw: status line, echoed identity, body.
func dhAck(raw, status, body string) string {
	return "HTTP/1.1 " + status + "\r\n" + echoIdentity(raw) + "\r\n" + body
}

// defaultRespond answers the DH request repertoire of verifyDevice and the
// tunnel handshake. All addresses point back at the peer itself; PTCP
// frames are dropped (the handshake's PTCP reads then time out).
func (p *dhTestPeer) defaultRespond(raw string) string {
	if strings.HasPrefix(raw, "PTCP") {
		return ""
	}
	line := raw
	if i := strings.Index(raw, "\r\n"); i >= 0 {
		line = raw[:i]
	}
	switch {
	case strings.Contains(line, "/online/p2psrv/"):
		return "HTTP/1.1 200 OK\r\n\r\n<body><US>127.0.0.1:" + strconv.Itoa(p.port) + "</US></body>"
	case strings.Contains(line, "/info/device/"):
		info := encryptDevInfoInfo([]byte(`{"randsalt":"` + testSalt + `","devP2PVersion":"3.0"}`))
		return "HTTP/1.1 200 OK\r\n\r\n<body><Info>" + info + "</Info></body>"
	case strings.Contains(line, "/p2p-channel"):
		return dhAck(raw, "200 OK",
			"<body><PubAddr>127.0.0.1:25024</PubAddr>"+
				"<LocalAddr>127.0.0.1:25025</LocalAddr><Policy>p2p,udprelay</Policy></body>")
	case strings.Contains(line, "/online/relay"):
		return "HTTP/1.1 200 OK\r\n\r\n<body><Address>127.0.0.1:" + strconv.Itoa(p.port) + "</Address></body>"
	case strings.Contains(line, "/relay/agent"):
		return "HTTP/1.1 200 OK\r\n\r\n<body><Token>testtoken</Token><Agent>127.0.0.1:" +
			strconv.Itoa(p.port) + "</Agent></body>"
	}
	return "HTTP/1.1 200 OK\r\n\r\n"
}

// resetTestCSeq restarts the global CSeq counter so sequence tests can
// assert the absolute CSeq progression a fresh process would emit.
func resetTestCSeq(t *testing.T) {
	t.Helper()
	cseqLock.Lock()
	cseq = 0
	cseqLock.Unlock()
}

// The dmss dialect draws random SIGNED-int32 CSeq values (negatives legal —
// the app does too), so the optional sign is part of the grammar; smartpss
// keeps non-negative counter values, which the pattern also matches.
var cseqRe = regexp.MustCompile(`CSeq: (-?\d+)\r\n`)

func cseqOf(t *testing.T, req string) int {
	t.Helper()
	m := cseqRe.FindStringSubmatch(req)
	if m == nil {
		t.Fatalf("no CSeq in request:\n%s", req)
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("CSeq parse: %v", err)
	}
	return n
}

func requestLine(raw string) string {
	if i := strings.Index(raw, "\r\n"); i >= 0 {
		return raw[:i]
	}
	return raw
}

// dhRequests returns the recorded DH requests, filtering PTCP frames (the
// handshake's PTCP sync travels to the same scripted peer).
func dhRequests(p *dhTestPeer) []string {
	var out []string
	for _, raw := range p.requests() {
		if !strings.HasPrefix(raw, "PTCP") {
			out = append(out, raw)
		}
	}
	return out
}

func newTestPeerProfile(p *dhTestPeer) *appProfile {
	prof := *dmssProfile
	prof.mainServer = "127.0.0.1"
	prof.mainPort = p.port
	return &prof
}

func dmssTestSpecs() []PortSpec {
	return []PortSpec{{Local: 0, Remote: 80}, {Local: 0, Remote: 37777}}
}

// B1: the dmss preflight must exercise the full channel machinery — AutoSalt
// resolved from the encrypted Info blob before signing, x-pcs-request-id on
// the wire, ClientId advertising a real forwarded port — and return the
// resolved salt for the per-port tunnels to reuse.
func TestVerifyDeviceDMSSPreflight(t *testing.T) {
	resetTestCSeq(t)
	p := newDHTestPeer(t)
	prof := newTestPeerProfile(p)

	ok, salt := verifyDevice("SN123", prof, 1, "admin", "pw", "", dmssTestSpecs(), false)
	if !ok {
		t.Fatal("verifyDevice reported the device as unreachable")
	}
	if salt != testSalt {
		t.Fatalf("resolved salt = %q, want %q", salt, testSalt)
	}

	reqs := p.requests()
	if len(reqs) != 5 {
		t.Fatalf("got %d requests, want 5 (warmup, p2psrv, probe, info, channel):\n%s",
			len(reqs), strings.Join(reqs, "\n---\n"))
	}
	// CSeq: the dmss dialect allocates a random SIGNED-int32 per logical
	// request (app behavior; the legacy counter shape drew 403 live), so
	// there is no counter progression to assert — every request's CSeq must
	// instead parse as a signed int32 (parse-and-verify, not pin).
	for i, req := range reqs {
		if got := cseqOf(t, req); got < -(1<<31) || got >= 1<<31 {
			t.Fatalf("request %d (%s) CSeq %d out of signed-int32 range", i, requestLine(req), got)
		}
	}

	ch := reqs[4]
	if want := "NFPOST /device/SN123/p2p-channel HTTP/1.1\r\n"; !strings.HasPrefix(ch, want) {
		t.Fatalf("channel request line drifted.\ngot:  %q\nwant: %q", requestLine(ch), want)
	}
	// Live-proven serialization: the version headers and the pcs-id precede
	// CSeq (the app's order — the discriminator the cloud accepts).
	if strings.Index(ch, "X-Version: 6.7.15") > strings.Index(ch, "CSeq: ") {
		t.Fatalf("X-Version not before CSeq (app header order):\n%s", ch)
	}
	if m, _ := regexp.MatchString(`x-pcs-request-id: [0-9a-f]{32}\r\n`, ch); !m {
		t.Fatalf("channel request missing x-pcs-request-id:\n%s", ch)
	}
	if strings.Index(ch, "x-pcs-request-id: ") > strings.Index(ch, "CSeq: ") {
		t.Fatalf("x-pcs-request-id not before CSeq (app header order):\n%s", ch)
	}
	for _, hdr := range []string{"X-Version: 6.7.15\r\n", "X-Sversion: 1.1.0\r\n", "X-ToUType: Client/Dmss_Android\r\n"} {
		if !strings.Contains(ch, hdr) {
			t.Fatalf("channel request missing %q:\n%s", hdr, ch)
		}
	}

	_, body, _ := strings.Cut(ch, "\r\n\r\n")
	for _, frag := range []string{
		"<IpEncrptV2>true</IpEncrptV2>",
		"<UserName>admin</UserName>",
		"<RandSalt>" + testSalt + "</RandSalt>", // resolved salt, not the empty default
	} {
		if !strings.Contains(body, frag) {
			t.Fatalf("channel body missing %q:\n%s", frag, body)
		}
	}

	// ClientId must advertise a real forwarded port — the first camera port
	// of the -p map, not :0.
	clientID := regexp.MustCompile(`<ClientId>([^<]+)</ClientId>`).FindStringSubmatch(body)
	if clientID == nil {
		t.Fatalf("channel body missing ClientId:\n%s", body)
	}
	if m, _ := regexp.MatchString(`^[0-9a-f]{32}:80$`, clientID[1]); !m {
		t.Fatalf("ClientId = %q, want \"<32 hex>:80\" (first forwarded port)", clientID[1])
	}

	// The auth block must be signed with the RESOLVED salt: recompute the
	// signature from the wire fields and compare byte for byte.
	nonceS := regexp.MustCompile(`<Nonce>(-?\d+)</Nonce>`).FindStringSubmatch(body)
	createdS := regexp.MustCompile(`<CreateDate>(\d+)</CreateDate>`).FindStringSubmatch(body)
	laddrEnc := regexp.MustCompile(`<LocalAddr>([^<]+)</LocalAddr>`).FindStringSubmatch(body)
	devauth := regexp.MustCompile(`<DevAuth>([^<]+)</DevAuth>`).FindStringSubmatch(body)
	if nonceS == nil || createdS == nil || laddrEnc == nil || devauth == nil {
		t.Fatalf("auth block incomplete:\n%s", body)
	}
	nonce, _ := strconv.Atoi(nonceS[1])
	created, _ := strconv.ParseInt(createdS[1], 10, 64)
	key := getDeriveKey("admin", "pw", testSalt)
	block := getAuthAt("admin", key, nonce, laddrEnc[1], testSalt, created)
	want := regexp.MustCompile(`<DevAuth>([^<]+)</DevAuth>`).FindStringSubmatch(block)
	if want == nil {
		t.Fatalf("recomputed auth block malformed:\n%s", block)
	}
	if devauth[1] != want[1] {
		t.Fatalf("DevAuth not signed with the resolved salt.\ngot:  %s\nwant: %s", devauth[1], want[1])
	}
	// The encrypted LocalAddr decrypts to the app's CSV shape: at least one
	// bare-IP interface prefix, then the preflight socket's own bind
	// address (loopback here) as the final host:port entry.
	if laddr := getDec(key, nonce, laddrEnc[1]); !regexp.MustCompile(`^\d{1,3}(?:\.\d{1,3}){3}(?:,\d{1,3}(?:\.\d{1,3}){3})*,127\.0\.0\.1:\d+$`).MatchString(laddr) {
		t.Fatalf("decrypted LocalAddr = %q, want CSV prefixes + 127.0.0.1:<port>", laddr)
	}
}

// B1: the preflight applies the app-style retransmission — the same logical
// request (CSeq, Identify, ClientId, x-pcs-request-id) goes out again with
// fresh crypto (Nonce, DevAuth, LocalAddr) when the first datagram is lost.
func TestVerifyDeviceDMSSRetransmit(t *testing.T) {
	resetTestCSeq(t)
	p := newDHTestPeer(t)
	prof := newTestPeerProfile(p)

	var mu sync.Mutex
	sends := 0
	p.setRespFn(func(raw string) (string, bool) {
		if strings.HasPrefix(raw, "NFPOST /device/SN123/p2p-channel") {
			mu.Lock()
			sends++
			n := sends
			mu.Unlock()
			if n == 1 {
				return "", true // first send lost — peer stays silent
			}
			return dhAck(raw, "200 OK",
				"<body><PubAddr>127.0.0.1:25024</PubAddr>"+
					"<LocalAddr>127.0.0.1:25025</LocalAddr></body>"), true
		}
		return "", false
	})

	ok, salt := verifyDevice("SN123", prof, 1, "admin", "pw", "", dmssTestSpecs(), false)
	if !ok {
		t.Fatal("verifyDevice failed despite the retransmitted ack")
	}
	if salt != testSalt {
		t.Fatalf("resolved salt = %q, want %q", salt, testSalt)
	}

	mu.Lock()
	n := sends
	mu.Unlock()
	if n != 2 {
		t.Fatalf("channel sends = %d, want 2 (one retransmission)", n)
	}
	var chans []string
	for _, raw := range p.requests() {
		if strings.HasPrefix(raw, "NFPOST /device/SN123/p2p-channel") {
			chans = append(chans, raw)
		}
	}
	if len(chans) != 2 {
		t.Fatalf("captured %d channel requests, want 2", len(chans))
	}

	id := func(raw string) (cseq, identify, clientID, pcsID, nonce string) {
		cseq = cseqRe.FindStringSubmatch(raw)[1]
		_, body, _ := strings.Cut(raw, "\r\n\r\n")
		identify = regexp.MustCompile(`<Identify>([^<]+)</Identify>`).FindStringSubmatch(body)[1]
		clientID = regexp.MustCompile(`<ClientId>([^<]+)</ClientId>`).FindStringSubmatch(body)[1]
		pcsID = regexp.MustCompile(`x-pcs-request-id: ([0-9a-f]+)\r\n`).FindStringSubmatch(raw)[1]
		nonce = regexp.MustCompile(`<Nonce>(-?\d+)</Nonce>`).FindStringSubmatch(body)[1]
		return cseq, identify, clientID, pcsID, nonce
	}
	c1, id1, cl1, pcs1, n1 := id(chans[0])
	c2, id2, cl2, pcs2, n2 := id(chans[1])
	if c1 != c2 || id1 != id2 || cl1 != cl2 || pcs1 != pcs2 {
		t.Fatalf("identity drifted across retransmission:\n  cseq %s/%s identify %s/%s clientid %s/%s pcsid %s/%s",
			c1, c2, id1, id2, cl1, cl2, pcs1, pcs2)
	}
	if n1 == n2 {
		t.Fatalf("Nonce not refreshed across retransmission: %s", n1)
	}
}

// --- M4: local-channel parity must never block tunnel establishment ---

// newLocalChannelTunnel builds a dmss Type-1 tunnel wired to the scripted
// peer with the channel key sendLocalChannel signs with.
func newLocalChannelTunnel(t *testing.T, p *dhTestPeer) *Tunnel {
	t.Helper()
	prof := *dmssProfile
	prof.mainServer = "127.0.0.1"
	prof.mainPort = p.port
	tt := newTunnel("SN123", &prof, 1, "admin", "pw", testSalt, false, false, false, 0, specGroup{}, nil)
	tt.chanKey = getDeriveKey("admin", "pw", testSalt)
	t.Cleanup(tt.close)
	return tt
}

// M4: the local-channel request keeps the app-parity wire form — profile
// GET verb, Type-1 auth block covering nonce+created only (no LocalAddr).
func TestSendLocalChannelWireForm(t *testing.T) {
	p := newDHTestPeer(t)
	tt := newLocalChannelTunnel(t, p)

	tt.sendLocalChannel(tt.localChannelStep())

	reqs := p.requests()
	if len(reqs) != 1 {
		t.Fatalf("got %d requests, want 1:\n%s", len(reqs), strings.Join(reqs, "\n---\n"))
	}
	req := reqs[0]
	if !strings.HasPrefix(req, "NFGET /device/SN123/local-channel HTTP/1.1\r\n") {
		t.Fatalf("request line drifted:\n%s", req)
	}
	if !strings.Contains(req, "Authorization: WSSE profile=\"UsernameToken\"\r\n") {
		t.Fatalf("local-channel request missing WSSE auth:\n%s", req)
	}
	_, body, _ := strings.Cut(req, "\r\n\r\n")
	for _, frag := range []string{"<body>", "<DevAuth>", "<Nonce>", "<CreateDate>", "<RandSalt>" + testSalt + "</RandSalt>", "<UserName>admin</UserName>", "</body>"} {
		if !strings.Contains(body, frag) {
			t.Fatalf("local-channel body missing %q:\n%s", frag, body)
		}
	}
	if strings.Contains(body, "<LocalAddr>") {
		t.Fatalf("local-channel body must not carry a LocalAddr:\n%s", body)
	}
}

// M4: an unresponsive endpoint must not stall the step — the ack read is
// bounded by localChannelAckTimeout and the step returns (establishment
// meanwhile proceeds: the call fires post-establishment, in a goroutine).
func TestSendLocalChannelBoundedOnSilentPeer(t *testing.T) {
	p := newDHTestPeer(t)
	tt := newLocalChannelTunnel(t, p)
	p.setRespFn(func(string) (string, bool) { return "", true }) // everything lost

	orig := localChannelAckTimeout
	localChannelAckTimeout = 100 * time.Millisecond
	defer func() { localChannelAckTimeout = orig }()

	start := time.Now()
	tt.sendLocalChannel(tt.localChannelStep())
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("unresponsive endpoint blocked sendLocalChannel for %v — bound is %v", elapsed, localChannelAckTimeout)
	}
}

// --- Regression (salt precedence): the input salt survives the handshake ---

// The dmss handshake re-probes the device's Info blob mid-establish
// (resolveAutoSalt in establish) — before the precedence fix that probe
// OVERWROTE a non-empty input salt with the blob's salt, so the salt the
// preflight (verifyDevice) had resolved and runMulti had assigned — or the
// user's explicit --randsalt — was silently replaced and the channel request
// was signed with the wrong key (DevAuth rejection). Both provenances of the
// input salt must survive: the emitted p2p-channel body carries the input
// salt and its DevAuth verifies byte-for-byte against it.
func TestHandshakeKeepsInputSaltAgainstInfoBlob(t *testing.T) {
	for _, tc := range []struct{ name, salt string }{
		{"preflight-resolved", "PR3FS4LT"}, // verifyDevice's return, assigned in runMulti
		{"explicit-flag", "FL4GS4LT"},      // DMSS --randsalt
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetTestCSeq(t)
			p := newDHTestPeer(t)
			prof := newTestPeerProfile(p) // peer's Info blob carries testSalt ("salt B")

			orig := RELAY_READ_TIMEOUT
			RELAY_READ_TIMEOUT = 250 * time.Millisecond
			defer func() { RELAY_READ_TIMEOUT = orig }()

			tt := newTunnel("SN123", prof, 1, "admin", "pw", tc.salt, false, false, false, 0, specGroup{}, nil)
			defer tt.close()

			// The scripted peer drops PTCP frames, so the handshake fails at
			// the ptcp-sync read — after the channel request has hit the wire.
			if err := tt.handshake(); err == nil {
				t.Fatal("handshake unexpectedly succeeded without a PTCP peer")
			}

			var ch string
			for _, raw := range p.requests() {
				if strings.HasPrefix(raw, "NFPOST /device/SN123/p2p-channel") {
					ch = raw
				}
			}
			if ch == "" {
				t.Fatalf("no p2p-channel request captured:\n%s", strings.Join(dhRequests(p), "\n---\n"))
			}
			_, body, _ := strings.Cut(ch, "\r\n\r\n")
			if !strings.Contains(body, "<RandSalt>"+tc.salt+"</RandSalt>") {
				t.Fatalf("channel body not carrying the input salt %q:\n%s", tc.salt, body)
			}
			if strings.Contains(body, testSalt) {
				t.Fatalf("channel body carries the Info-blob salt %q:\n%s", testSalt, body)
			}

			// The DevAuth signature must verify byte-for-byte with the input
			// salt's key — and must NOT match the blob salt's key.
			nonceS := regexp.MustCompile(`<Nonce>(-?\d+)</Nonce>`).FindStringSubmatch(body)
			createdS := regexp.MustCompile(`<CreateDate>(\d+)</CreateDate>`).FindStringSubmatch(body)
			laddrEnc := regexp.MustCompile(`<LocalAddr>([^<]+)</LocalAddr>`).FindStringSubmatch(body)
			devauth := regexp.MustCompile(`<DevAuth>([^<]+)</DevAuth>`).FindStringSubmatch(body)
			if nonceS == nil || createdS == nil || laddrEnc == nil || devauth == nil {
				t.Fatalf("auth block incomplete:\n%s", body)
			}
			nonce, _ := strconv.Atoi(nonceS[1])
			created, _ := strconv.ParseInt(createdS[1], 10, 64)
			authWith := func(salt string) string {
				key := getDeriveKey("admin", "pw", salt)
				block := getAuthAt("admin", key, nonce, laddrEnc[1], salt, created)
				return regexp.MustCompile(`<DevAuth>([^<]+)</DevAuth>`).FindStringSubmatch(block)[1]
			}
			if devauth[1] != authWith(tc.salt) {
				t.Fatalf("DevAuth not signed with the input salt %q", tc.salt)
			}
			if devauth[1] == authWith(testSalt) {
				t.Fatalf("DevAuth signed with the Info-blob salt %q — precedence regression", testSalt)
			}
		})
	}
}

// --- M4 (wrapper level): handshake returns promptly; the step is a snapshot ---

// ptcpReply builds a PTCP frame the scripted peer can answer the handshake
// with — Pid 0x0000FFFF (plain data), the given body.
func ptcpReply(body []byte) string {
	return string((&PTCP{Pid: 0x0000FFFF, Body: body}).Bytes())
}

// M4: handshake must return promptly with the local-channel peer silent —
// the step launches on a goroutine with a bounded ack read (shrunk here) and
// must never delay establishment. The step signs from the SNAPSHOT taken
// before the launch: reset() (as a reconnect cycle would) clears chanKey
// immediately after handshake returns, and the in-flight step still emits
// the exact app-parity wire form — go test -race polices the read side.
func TestHandshakeLocalChannelPromptAndSnapshotted(t *testing.T) {
	p := newDHTestPeer(t)
	tt := newLocalChannelTunnel(t, p)

	sign := []byte("SIGNSIGN")
	p.setRespFn(func(raw string) (string, bool) {
		switch {
		case strings.HasPrefix(raw, "NFGET /device/SN123/local-channel"):
			return "", true // the local-channel peer stays silent
		case strings.HasPrefix(raw, "NFPOST /device/SN123/p2p-channel"):
			// Point PubAddr at the peer so the STUN init and the PTCP frames
			// reach the scripted responder and establish completes (direct
			// path) instead of burning its 10 s STUN deadline.
			return dhAck(raw, "200 OK",
				"<body><PubAddr>127.0.0.1:"+strconv.Itoa(p.port)+"</PubAddr>"+
					"<LocalAddr>127.0.0.1:25025</LocalAddr><Policy>p2p,udprelay</Policy></body>"), true
		case strings.HasPrefix(raw, "PTCP"):
			if len(raw) < 25 {
				return "", true
			}
			body := raw[24:]
			switch {
			case len(body) == 4 && body[0] == 0x00 && body[1] == 0x03 && body[2] == 0x01 && body[3] == 0x00:
				return ptcpReply([]byte{0x00, 0x03, 0x01, 0x00}), true // sync echo
			case body[0] == 0x17:
				tok := append([]byte{0x17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, sign...)
				return ptcpReply(tok), true
			case body[0] == 0x19:
				return ptcpReply([]byte{0x1A, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}), true
			case body[0] == 0x1B:
				return ptcpReply(nil), true
			}
			return "", true // pure acks and anything else: stay silent
		case len(raw) >= 4 && raw[0] == '\xff' && raw[1] == '\xfe' && raw[2] == '\xff' && raw[3] == '\xe7':
			// STUN init → response magic (only the magic is checked).
			return string([]byte{0xfe, 0xfe, 0xff, 0xe7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}), true
		}
		return "", false
	})

	origRead := RELAY_READ_TIMEOUT
	RELAY_READ_TIMEOUT = 250 * time.Millisecond
	origAck := localChannelAckTimeout
	localChannelAckTimeout = 200 * time.Millisecond
	defer func() { RELAY_READ_TIMEOUT = origRead; localChannelAckTimeout = origAck }()

	start := time.Now()
	if err := tt.handshake(); err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("handshake took %v — the local-channel step must not delay establishment", elapsed)
	}

	// The step runs after the wrapper returned: clear the mutable state a
	// reset clears, exactly like a reconnect cycle racing the in-flight step.
	tt.reset()

	// The request must still hit the wire, signed from the snapshot: the
	// app-parity body with the tunnel's RandSalt (a nil chanKey from the
	// reset must not have leaked into the signature).
	deadline := time.Now().Add(2 * time.Second)
	for {
		var ch string
		for _, raw := range p.requests() {
			if strings.HasPrefix(raw, "NFGET /device/SN123/local-channel") {
				ch = raw
			}
		}
		if ch != "" {
			_, body, _ := strings.Cut(ch, "\r\n\r\n")
			for _, frag := range []string{"<RandSalt>" + testSalt + "</RandSalt>", "<UserName>admin</UserName>"} {
				if !strings.Contains(body, frag) {
					t.Fatalf("local-channel body missing %q after reset:\n%s", frag, body)
				}
			}
			// Byte-for-byte: the DevAuth must be signed with the snapshot's
			// channel key — not with whatever reset() left behind (a nil key
			// HMACs to a different digest even where the race is not hit).
			nonceS := regexp.MustCompile(`<Nonce>(-?\d+)</Nonce>`).FindStringSubmatch(body)
			createdS := regexp.MustCompile(`<CreateDate>(\d+)</CreateDate>`).FindStringSubmatch(body)
			devauth := regexp.MustCompile(`<DevAuth>([^<]+)</DevAuth>`).FindStringSubmatch(body)
			if nonceS == nil || createdS == nil || devauth == nil {
				t.Fatalf("local-channel auth block incomplete:\n%s", body)
			}
			nonce, _ := strconv.Atoi(nonceS[1])
			created, _ := strconv.ParseInt(createdS[1], 10, 64)
			key := getDeriveKey("admin", "pw", testSalt)
			want := getAuthAt("admin", key, nonce, "", testSalt, created)
			wantAuth := regexp.MustCompile(`<DevAuth>([^<]+)</DevAuth>`).FindStringSubmatch(want)[1]
			if devauth[1] != wantAuth {
				t.Fatalf("local-channel DevAuth not signed with the snapshot's chanKey")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("local-channel request never hit the wire after reset:\n%s",
				strings.Join(dhRequests(p), "\n---\n"))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// --- M1 regression: smartpss wire byte-identity vs upstream 7a65400b ---
//
// The expected sequences mirror upstream dh-fwd at 7a65400b:
//   - main.go verifyDevice: DHGET /probe/p2psrv → /online/p2psrv/<SN> →
//     p2pChannelBody (tunnel.go, pure body construction — no CSeq side
//     effect) → DHPOST /device/<SN>/p2p-channel via UDP.Request → ack reads.
//     Three requests, CSeq 1..3, no device-p2psrv traffic.
//   - tunnel.go handshake: /probe/p2psrv → /online/p2psrv/<SN> →
//     /probe/device/<SN> → /info/device/<SN> → /online/relay → channel →
//     /relay/agent → /relay/start/<token> → relay-channel; helpers.go
//     UDP.Request allocates one global CSeq per request.
//   - helpers.go buildDHRequest: the header layout reconstructed below.
//   - tunnel.go p2pChannelBody: the body layout. Two intentional deviations:
//     the type-1 DevAuth covers the ENCRYPTED LocalAddr (5fb3b5c) — upstream
//     signed the plaintext addr, which was dh-fwd's Type-1 bug; and the
//     LocalAddr payload is the app-format CSV of interface IPs + bind:port —
//     upstream sent a bare "127.0.0.1:<port>". The CSV is the DMSS app's
//     wire form and is kept for app parity: the earlier "single-entry → 403"
//     live bracket (2026-09-06) ran with dh-fwd's header serialization and is
//     confounded — later live evidence showed the header serialization was
//     the discriminator, not the CSV. The expected signatures below are
//     computed over the encrypted addr; LocalAddr values are matched
//     shape-wise.

// wsseHeader rebuilds the Authorization/X-WSSE header block exactly as
// upstream buildDHRequest emits it for the captured nonce/created.
func wsseHeader(nonce, created string) string {
	digest := wsseDigest(nonce, created, WSSE_USERNAME, WSSE_USERKEY)
	return "Authorization: WSSE profile=\"UsernameToken\"\r\n" +
		"X-WSSE: UsernameToken Username=\"" + WSSE_USERNAME +
		"\", PasswordDigest=\"" + digest + "\", Nonce=\"" + nonce +
		"\", Created=\"" + created + "\"\r\n"
}

func headerField(t *testing.T, req, name string) string {
	t.Helper()
	m := regexp.MustCompile(name + `="([^"]+)"`).FindStringSubmatch(req)
	if m == nil {
		t.Fatalf("header %s missing:\n%s", name, req)
	}
	return m[1]
}

// M1: the smartpss preflight keeps the upstream wire behavior — exactly the
// three upstream requests, CSeq 1..3 (the channel request under its own,
// singly-allocated CSeq — not shifted by a body-construction allocation),
// byte-identical request forms.
func TestVerifyDeviceSmartPSSUpstreamSequence(t *testing.T) {
	resetTestCSeq(t)
	p := newDHTestPeer(t)
	prof := *smartpssProfile
	prof.mainServer = "127.0.0.1"
	prof.mainPort = p.port

	ok, salt := verifyDevice("SN123", &prof, 1, "admin", "pw", "LegacySalt", dmssTestSpecs(), false)
	if !ok {
		t.Fatal("verifyDevice reported the device as unreachable")
	}
	if salt != "LegacySalt" {
		t.Fatalf("smartpss preflight mutated the salt: %q", salt)
	}

	reqs := p.requests()
	if len(reqs) != 3 {
		t.Fatalf("got %d requests, want 3 (upstream preflight never dials the device p2psrv):\n%s",
			len(reqs), strings.Join(reqs, "\n---\n"))
	}
	for i, want := range []int{1, 2, 3} {
		if got := cseqOf(t, reqs[i]); got != want {
			t.Fatalf("request %d (%s) CSeq = %d, want %d", i, requestLine(reqs[i]), got, want)
		}
	}

	// Request 1/2: upstream buildDHRequest with an empty body.
	nonce1 := headerField(t, reqs[0], `Nonce`)
	created1 := headerField(t, reqs[0], `Created`)
	want1 := "DHGET /probe/p2psrv HTTP/1.1\r\nCSeq: 1\r\n" + wsseHeader(nonce1, created1) + "\r\n"
	if reqs[0] != want1 {
		t.Fatalf("smartpss preflight probe bytes drifted.\ngot:\n%q\nwant:\n%q", reqs[0], want1)
	}
	nonce2 := headerField(t, reqs[1], `Nonce`)
	created2 := headerField(t, reqs[1], `Created`)
	want2 := "DHGET /online/p2psrv/SN123 HTTP/1.1\r\nCSeq: 2\r\n" + wsseHeader(nonce2, created2) + "\r\n"
	if reqs[1] != want2 {
		t.Fatalf("smartpss preflight p2psrv bytes drifted.\ngot:\n%q\nwant:\n%q", reqs[1], want2)
	}

	// Request 3: the channel request — upstream body form, upstream headers,
	// CSeq 3. The auth block is recomputed over the ENCRYPTED addr (the
	// intentional 5fb3b5c signing fix).
	_, body3, _ := strings.Cut(reqs[2], "\r\n\r\n")
	identify := regexp.MustCompile(`<Identify>([^<]+)</Identify>`).FindStringSubmatch(body3)
	laddrEnc := regexp.MustCompile(`<LocalAddr>([^<]+)</LocalAddr>`).FindStringSubmatch(body3)
	nonceB := regexp.MustCompile(`<Nonce>(-?\d+)</Nonce>`).FindStringSubmatch(body3)
	createdB := regexp.MustCompile(`<CreateDate>(\d+)</CreateDate>`).FindStringSubmatch(body3)
	if identify == nil || laddrEnc == nil || nonceB == nil || createdB == nil {
		t.Fatalf("channel body incomplete:\n%s", body3)
	}
	key := getDeriveKey("admin", "pw", "LegacySalt")
	nonce, _ := strconv.Atoi(nonceB[1])
	created, _ := strconv.ParseInt(createdB[1], 10, 64)
	auth := getAuthAt("admin", key, nonce, laddrEnc[1], "LegacySalt", created)
	wantBody := "<body>" + auth + "<Identify>" + identify[1] + "</Identify>" +
		"<IpEncrptV2>true</IpEncrptV2><LocalAddr>" + laddrEnc[1] + "</LocalAddr>" +
		"<version>5.0.0</version></body>"
	nonceH := headerField(t, reqs[2], `Nonce`)
	createdH := headerField(t, reqs[2], `Created`)
	want3 := "DHPOST /device/SN123/p2p-channel HTTP/1.1\r\nCSeq: 3\r\n" +
		wsseHeader(nonceH, createdH) +
		"Content-Type: \r\nContent-Length: " + strconv.Itoa(len(wantBody)) + "\r\n\r\n" + wantBody
	if reqs[2] != want3 {
		t.Fatalf("smartpss preflight channel request drifted.\ngot:\n%q\nwant:\n%q", reqs[2], want3)
	}
}

// M1: the smartpss handshake emits the full upstream request sequence with
// unshifted CSeq progression — the channel request stays at CSeq 6, exactly
// one allocation per logical request.
func TestHandshakeSmartPSSUpstreamSequence(t *testing.T) {
	resetTestCSeq(t)
	p := newDHTestPeer(t)
	prof := *smartpssProfile
	prof.mainServer = "127.0.0.1"
	prof.mainPort = p.port

	orig := RELAY_READ_TIMEOUT
	RELAY_READ_TIMEOUT = 250 * time.Millisecond
	defer func() { RELAY_READ_TIMEOUT = orig }()

	g := specGroup{idxs: []int{0, 1}, specs: []PortSpec{{Local: 0, Remote: 80}, {Local: 0, Remote: 37777}}}
	tt := newTunnel("SN123", &prof, 0, "", "", "", false, false, false, 0, g, nil)
	defer tt.close()

	// The scripted peer answers every DH request but drops PTCP frames, so
	// the handshake runs deterministically to the "ptcp sync" read timeout —
	// after the complete DH request sequence has hit the wire.
	if err := tt.handshake(); err == nil {
		t.Fatal("handshake unexpectedly succeeded without a PTCP peer")
	}

	reqs := dhRequests(p)
	wantLines := []string{
		"DHGET /probe/p2psrv HTTP/1.1",                // tunnel.go handshake phase 1 (upstream: Request)
		"DHGET /online/p2psrv/SN123 HTTP/1.1",         // upstream: Request
		"DHGET /probe/device/SN123 HTTP/1.1",          // upstream: device-p2psrv warm-up Request
		"DHGET /info/device/SN123 HTTP/1.1",           // upstream: Request
		"DHGET /online/relay HTTP/1.1",                // upstream: Request
		"DHPOST /device/SN123/p2p-channel HTTP/1.1",   // upstream: p2pChannelBody + Request
		"DHGET /relay/agent HTTP/1.1",                 // upstream: Request
		"DHPOST /relay/start/testtoken HTTP/1.1",      // upstream: Request
		"DHPOST /device/SN123/relay-channel HTTP/1.1", // upstream: sendRelayChannel Request
	}
	if len(reqs) != len(wantLines) {
		t.Fatalf("got %d requests, want %d:\n%s", len(reqs), len(wantLines), strings.Join(reqs, "\n---\n"))
	}
	for i, want := range wantLines {
		if got := requestLine(reqs[i]); got != want {
			t.Fatalf("request %d = %q, want %q", i, got, want)
		}
		if got := cseqOf(t, reqs[i]); got != i+1 {
			t.Fatalf("request %d (%s) CSeq = %d, want %d", i, want, got, i+1)
		}
	}

	// Byte-identical forms: the probe and the channel request, rebuilt from
	// upstream buildDHRequest / p2pChannelBody (type 0).
	nonce1 := headerField(t, reqs[0], `Nonce`)
	created1 := headerField(t, reqs[0], `Created`)
	want1 := "DHGET /probe/p2psrv HTTP/1.1\r\nCSeq: 1\r\n" + wsseHeader(nonce1, created1) + "\r\n"
	if reqs[0] != want1 {
		t.Fatalf("smartpss handshake probe bytes drifted.\ngot:\n%q\nwant:\n%q", reqs[0], want1)
	}

	_, body6, _ := strings.Cut(reqs[5], "\r\n\r\n")
	identify := regexp.MustCompile(`<Identify>([^<]+)</Identify>`).FindStringSubmatch(body6)
	laddr := regexp.MustCompile(`<LocalAddr>([^<]+)</LocalAddr>`).FindStringSubmatch(body6)
	if identify == nil || laddr == nil {
		t.Fatalf("channel body incomplete:\n%s", body6)
	}
	wantBody := "<body><Identify>" + identify[1] + "</Identify>" +
		"<IpEncrpt>true</IpEncrpt><LocalAddr>" + laddr[1] + "</LocalAddr>" +
		"<version>5.0.0</version></body>"
	// The LocalAddr payload is the app-format CSV (the second intentional
	// deviation): bare-IP prefixes, final entry the channel socket's
	// loopback bind.
	if m, _ := regexp.MatchString(`<LocalAddr>(?:\d{1,3}(?:\.\d{1,3}){3},)+127\.0\.0\.1:\d+</LocalAddr>`, body6); !m {
		t.Fatalf("LocalAddr not the CSV form with the channel socket's loopback bind:\n%s", body6)
	}
	if body6 != wantBody {
		t.Fatalf("smartpss handshake channel body drifted.\ngot:\n%q\nwant:\n%q", body6, wantBody)
	}
	nonceH := headerField(t, reqs[5], `Nonce`)
	createdH := headerField(t, reqs[5], `Created`)
	want6 := fmt.Sprintf("DHPOST /device/SN123/p2p-channel HTTP/1.1\r\nCSeq: 6\r\n%s"+
		"Content-Type: \r\nContent-Length: %d\r\n\r\n%s",
		wsseHeader(nonceH, createdH), len(wantBody), wantBody)
	if reqs[5] != want6 {
		t.Fatalf("smartpss handshake channel request drifted.\ngot:\n%q\nwant:\n%q", reqs[5], want6)
	}

	// The relay-channel body advertises the agent address the peer handed out.
	if !strings.Contains(reqs[8], "<agentAddr>127.0.0.1:"+strconv.Itoa(p.port)+"</agentAddr>") {
		t.Fatalf("relay-channel body missing the agent address:\n%s", reqs[8])
	}
}
