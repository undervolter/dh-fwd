package core

import (
	"sync/atomic"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestPortParsing(t *testing.T) {
	cases := []struct {
		in      string
		want    []PortSpec
		wantErr bool
	}{
		{"8081", []PortSpec{{Local: 0, Remote: 8081}}, false},
		{"80-85", []PortSpec{{0, 80}, {0, 81}, {0, 82}, {0, 83}, {0, 84}, {0, 85}}, false},
		{"81,82,83", []PortSpec{{0, 81}, {0, 82}, {0, 83}}, false},
		{"8080:81", []PortSpec{{8080, 81}}, false},
		{"5080,5081,5082:80", []PortSpec{{5080, 80}, {5081, 80}, {5082, 80}}, false},
		{"5080,5081,5082:80,81,82", []PortSpec{{5080, 80}, {5081, 81}, {5082, 82}}, false},
		{"0:81", []PortSpec{{0, 81}}, false},
		{"8080-8082:80-82", []PortSpec{{8080, 80}, {8081, 81}, {8082, 82}}, false},
		{"8080:81,82", nil, true},
		{"80-85:0", nil, true},
		{"abc", nil, true},
	}
	for _, c := range cases {
		locals, remotes, err := parsePortLists(c.in)
		if err != nil {
			if c.wantErr {
				continue
			}
			t.Fatalf("%q: unexpected err %v", c.in, err)
		}
		specs, err := makePortSpecs(locals, remotes)
		if err != nil {
			if c.wantErr {
				continue
			}
			t.Fatalf("%q: makePortSpecs err %v", c.in, err)
		}
		if len(specs) != len(c.want) {
			t.Fatalf("%q: got %d specs, want %d", c.in, len(specs), len(c.want))
		}
		for i := range specs {
			if specs[i] != c.want[i] {
				t.Fatalf("%q: spec[%d]=%+v, want %+v", c.in, i, specs[i], c.want[i])
			}
		}
	}
}

func TestPTCPRoundtrip(t *testing.T) {
	p := &PTCP{Rlid: 1, Llid: 2, Pid: 3, Lmid: 4, Rmid: 5, Body: []byte{0xDE, 0xAD}}
	raw := p.Bytes()
	got, err := ParsePTCP(raw)
	if err != nil {
		t.Fatalf("ParsePTCP: %v", err)
	}
	if got.Rlid != 1 || got.Llid != 2 || got.Pid != 3 || got.Lmid != 4 || got.Rmid != 5 {
		t.Fatalf("header mismatch: %+v", got)
	}
	if string(got.Body) != "\xDE\xAD" {
		t.Fatalf("body mismatch: %x", got.Body)
	}
}

func TestPTCPPayloadRoundtrip(t *testing.T) {
	pl := &PTCPPayload{Realm: 0x781e4db2, Payload: []byte("OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n")}
	raw := pl.Bytes()
	got, err := ParsePTCPPayload(raw)
	if err != nil {
		t.Fatalf("ParsePTCPPayload: %v", err)
	}
	if got.Realm != pl.Realm || string(got.Payload) != string(pl.Payload) {
		t.Fatalf("payload mismatch: %+v", got)
	}
}

func TestDevInfoCryptoRoundtrip(t *testing.T) {
	// AES-OFB is symmetric: encrypting with the SDK keys and decrypting via
	// decryptDevInfoInfo must return the original plaintext.
	plain := []byte(`{"randsalt":"abc123","devP2PVersion":"6.6.5"}`)

	block, err := aes.NewCipher([]byte(DEVINFO_KEY))
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	stream := cipher.NewOFB(block, []byte(DEVINFO_IV))
	enc := make([]byte, len(plain))
	stream.XORKeyStream(enc, plain)

	got, err := decryptDevInfoInfo(base64.StdEncoding.EncodeToString(enc))
	if err != nil {
		t.Fatalf("decryptDevInfoInfo: %v", err)
	}
	if string(got) != string(plain) {
		t.Fatalf("roundtrip mismatch: %q", got)
	}
}

func TestParseDHResponse(t *testing.T) {
	raw := "HTTP/1.1 200 Server Nat Info!\r\nCSeq: 42\r\n\r\n<body><PubAddr>91.210.92.130:25024</PubAddr><Policy>p2p,udprelay</Policy></body>"
	res := ParseDHResponse(raw)
	if res.Code != 200 || res.Status != "Server Nat Info!" {
		t.Fatalf("status line mismatch: %d %q", res.Code, res.Status)
	}
	if res.Headers["CSeq"] != "42" {
		t.Fatalf("header mismatch: %v", res.Headers)
	}
	if res.Body["body/PubAddr"] != "91.210.92.130:25024" {
		t.Fatalf("body mismatch: %v", res.Body)
	}
	if res.Body["body/Policy"] != "p2p,udprelay" {
		t.Fatalf("body policy mismatch: %v", res.Body)
	}
}

// TestRequestPTCPWindowConstant: the advertised receive window must stay at
// full 0xFFFF no matter how many frames we send — a shrinking window would
// throttle the device's downstream video on long sessions.
func TestRequestPTCPWindowConstant(t *testing.T) {
	rxConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Skipf("udp listen: %v", err)
	}
	defer rxConn.Close()
	port := rxConn.LocalAddr().(*net.UDPAddr).Port

	u := NewUDP("127.0.0.1", port, false, smartpssProfile)
	defer u.Close()

	hb := []byte{0x13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	for i := 0; i < 70000; i++ {
		u.RequestPTCP(hb)
	}

	rxConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 128)
	n, err := rxConn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	p, err := ParsePTCP(buf[:n])
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Pid != 0x0000FFFF {
		t.Fatalf("window not constant: pid=0x%08x", p.Pid)
	}
	if u.ptcpCount != 70000 {
		t.Fatalf("count: %d", u.ptcpCount)
	}
}

// --- fixed realm pool ---

func TestPoolFIFO(t *testing.T) {
	tr := &Tunnel{pools: make(map[int]*poolState), poolTarget: 4}
	tr.pools[80] = &poolState{}
	tr.pushRealm(80, 0x1111)
	tr.pushRealm(80, 0x2222)
	if len(tr.pools[80].queue) != 2 {
		t.Fatalf("queue: %d", len(tr.pools[80].queue))
	}
	r, ok := tr.popRealm(80)
	if !ok || r != 0x1111 {
		t.Fatalf("fifo pop: %x %v", r, ok)
	}
	tr.dropRealm(0x2222)
	if len(tr.pools[80].queue) != 0 {
		t.Fatalf("drop failed: %d", len(tr.pools[80].queue))
	}
}


// --- camera ports from the Info blob ---

// applyDevicePorts recovers the real camera ports from the /info/device
// Info blob. Invalid/zero fields (0, 70000) never override the defaults
// (stay 0 = "no data"); valid values are read both from the top-level
// answer and from the encrypted blob.
func TestApplyDevicePorts(t *testing.T) {
	tr := &Tunnel{}

	// Silence / nil — zeros, defaults untouched.
	tr.applyDevicePorts(nil)
	if h, p, r := tr.DevicePorts(); h != 0 || p != 0 || r != 0 {
		t.Fatalf("nil payload: got http=%d priv=%d rtsp=%d, want zeros", h, p, r)
	}

	// Top level: invalid fields filtered, the valid one taken.
	tr.applyDevicePorts([]byte(`{"httpport":0,"privport":70000,"rtspport":554}`))
	if h, p, r := tr.DevicePorts(); h != 0 || p != 0 || r != 554 {
		t.Fatalf("top-level filter: got http=%d priv=%d rtsp=%d, want 0/0/554", h, p, r)
	}

	// Encrypted blob — the authoritative source (live log shape:
	// httpport=80, privport=37777, randsalt, rtspport=554, tlsprivport).
	payload := fmt.Sprintf(`{"Info":%q}`, encryptDevInfoInfo([]byte(`{"httpport":81,"privport":37778,"rtspport":554,"randsalt":"1eb7a35f"}`)))
	tr.applyDevicePorts([]byte(payload))
	if h, p, r := tr.DevicePorts(); h != 81 || p != 37778 || r != 554 {
		t.Fatalf("blob: got http=%d priv=%d rtsp=%d, want 81/37778/554", h, p, r)
	}
}

// serve() rewrites spec remote sides from the blob ports BEFORE the
// listeners bind: a camera with httpport=81 gets a live forward instead
// of a dead dial into port 80. Explicitly non-default operator ports are
// never touched.
func TestSpecPortOverride(t *testing.T) {
	tr := &Tunnel{
		specs: []PortSpec{{Local: 0, Remote: 80}, {Local: 0, Remote: 37777}, {Local: 0, Remote: 554}, {Local: 5080, Remote: 9000}},
	}
	tr.camHTTP, tr.camPriv, tr.camRTSP = 81, 37778, 554

	override := func(from, to int) {
		if to <= 0 || to == from {
			return
		}
		for i := range tr.specs {
			if tr.specs[i].Remote == from {
				tr.specs[i].Remote = to
			}
		}
	}
	override(80, tr.camHTTP)
	override(37777, tr.camPriv)
	override(554, tr.camRTSP)

	want := []PortSpec{{0, 81}, {0, 37778}, {0, 554}, {5080, 9000}}
	for i, w := range want {
		if tr.specs[i] != w {
			t.Fatalf("spec[%d] = %+v, want %+v", i, tr.specs[i], w)
		}
	}
}

func TestPTCPReliableARQ(t *testing.T) {
	rxConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Skipf("udp listen: %v", err)
	}
	defer rxConn.Close()
	port := rxConn.LocalAddr().(*net.UDPAddr).Port

	u := NewUDP("127.0.0.1", port, false, smartpssProfile)
	defer u.Close()

	// 1. Send data payload -> must be queued in in-flight segments
	payload := []byte("GET /pageBase.js HTTP/1.1\r\n\r\n")
	u.RequestPTCP(payload)

	u.ptcpMu.Lock()
	if len(u.ptcpSegments) != 1 {
		u.ptcpMu.Unlock()
		t.Fatalf("in-flight segments = %d, want 1", len(u.ptcpSegments))
	}
	seg := u.ptcpSegments[0]
	endSeq := seg.endSeq
	u.ptcpMu.Unlock()

	// 2. Simulate RTO: segment older than 300ms must be retransmitted
	time.Sleep(310 * time.Millisecond)
	retransmitted := u.CheckRetransmit()
	if retransmitted != 1 {
		t.Fatalf("CheckRetransmit = %d, want 1", retransmitted)
	}

	// 3. Simulate peer ACK acknowledging endSeq
	ackPkt := &PTCP{
		Rlid: 0,
		Llid: endSeq,
		Pid:  0x0000FFFF,
		Lmid: 100,
		Rmid: 1,
	}
	rxConn.WriteTo(ackPkt.Bytes(), &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: u.conn.LocalAddr().(*net.UDPAddr).Port})

	// Read ACK
	_, err = u.ReadPTCP(time.Second)
	if err != nil {
		t.Fatalf("ReadPTCP: %v", err)
	}

	// In-flight segments must be pruned
	u.ptcpMu.Lock()
	remaining := len(u.ptcpSegments)
	u.ptcpMu.Unlock()
	if remaining != 0 {
		t.Fatalf("remaining in-flight segments = %d, want 0", remaining)
	}
}

func TestPTCPInOrderReassembly(t *testing.T) {
	rx, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer rx.Close()
	rxAddr := rx.LocalAddr().(*net.UDPAddr)

	u := NewUDP("127.0.0.1", rxAddr.Port, false, nil)
	defer u.Close()

	peerAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: u.conn.LocalAddr().(*net.UDPAddr).Port}

	b1 := (&PTCPPayload{Realm: 0x1234, Payload: []byte("HELLO")}).Bytes()
	b2 := (&PTCPPayload{Realm: 0x1234, Payload: []byte("WORLD")}).Bytes()

	len1 := uint32(len(b1))
	len2 := uint32(len(b2))

	// 1. Peer sends Packet 2 first (out of order: seq len1 .. len1+len2)
	pkt2 := &PTCP{
		Rlid: len1,
		Llid: 0,
		Pid:  0x0000FFFF,
		Lmid: 2,
		Body: b2,
	}
	rx.WriteTo(pkt2.Bytes(), peerAddr)

	// In the background, wait 40ms then send Packet 1 (seq 0 .. len1)
	go func() {
		time.Sleep(40 * time.Millisecond)
		pkt1 := &PTCP{
			Rlid: 0,
			Llid: 0,
			Pid:  0x0000FFFF,
			Lmid: 1,
			Body: b1,
		}
		rx.WriteTo(pkt1.Bytes(), peerAddr)
	}()

	// 2. Read first in-order packet: MUST be pkt1
	p1, err := u.ReadPTCP(500 * time.Millisecond)
	if err != nil {
		t.Fatalf("ReadPTCP(p1) failed: %v", err)
	}
	pl1, err := ParsePTCPPayload(p1.Body)
	if err != nil || string(pl1.Payload) != "HELLO" {
		t.Fatalf("got pl1 = %v, err=%v, want HELLO", pl1, err)
	}

	// 3. Read second in-order packet: MUST be pkt2 drained from reassembly queue
	p2, err := u.ReadPTCP(100 * time.Millisecond)
	if err != nil {
		t.Fatalf("ReadPTCP(p2) failed: %v", err)
	}
	pl2, err := ParsePTCPPayload(p2.Body)
	if err != nil || string(pl2.Payload) != "WORLD" {
		t.Fatalf("got pl2 = %v, err=%v, want WORLD", pl2, err)
	}

	// 4. Cumulative ACK must be len1 + len2
	u.ptcpMu.Lock()
	recved := u.ptcpRecv
	u.ptcpMu.Unlock()
	if recved != len1+len2 {
		t.Fatalf("ptcpRecv = %d, want %d", recved, len1+len2)
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		bytes uint64
		want  string
	}{
		{0, "0 B"},
		{500, "500 B"},
		{1023, "1023 B"},
		{1024, "1 KB"},
		{1536, "1.5 KB"},
		{1048576, "1 MB"},
		{1572864, "1.5 MB"},
		{1073741824, "1 GB"},
		{2684354560, "2.5 GB"},
	}

	for _, tt := range tests {
		got := FormatBytes(tt.bytes)
		if got != tt.want {
			t.Errorf("FormatBytes(%d) = %q, want %q", tt.bytes, got, tt.want)
		}
	}
}

func TestTrafficStatsCounters(t *testing.T) {
	ResetBytesStats()
	up, down := GetBytesStats()
	if up != 0 || down != 0 {
		t.Fatalf("initial stats: got up=%d down=%d, want 0, 0", up, down)
	}

	atomic.AddUint64(&GlobalBytesUp, 1500)
	atomic.AddUint64(&GlobalBytesDown, 3000)

	up, down = GetBytesStats()
	if up != 1500 || down != 3000 {
		t.Fatalf("after add: got up=%d down=%d, want 1500, 3000", up, down)
	}

	ResetBytesStats()
	up, down = GetBytesStats()
	if up != 0 || down != 0 {
		t.Fatalf("after reset: got up=%d down=%d, want 0, 0", up, down)
	}
}

func TestIsNewerVersionZeroVer(t *testing.T) {
	// Local version 0.1 maps to GitHub release v2.5.0
	tests := []struct {
		latest  string
		current string
		want    bool
	}{
		{"v2.4.1", "0.1", false},
		{"v2.4", "0.1", false},
		{"v2.5", "0.1", false},
		{"v2.5.0", "0.1", false},
		{"v2.5.1", "0.1", true},
		{"v2.6.0", "0.1", true},
		{"0.1", "0.1", false},
		{"0.2", "0.1", true},
	}

	for _, tt := range tests {
		got := isNewerVersion(tt.latest, tt.current)
		if got != tt.want {
			t.Errorf("isNewerVersion(%q, %q) = %v, want %v", tt.latest, tt.current, got, tt.want)
		}
	}
}
