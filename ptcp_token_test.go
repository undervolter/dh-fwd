package main

import (
	"net"
	"testing"
	"time"
)

// Regression tests for waitForPTCPToken (live gate round 3, 2026-09-06):
// the relay agent's late 4-byte SYNC ack used to satisfy the old
// "non-empty body" guard in establish's 0x17 wait and panic the
// sign := p.Body[12:] slice (slice bounds [12:4]). The token waiter must
// drain such short frames and only return a plausible token body.

// sendPTCPFrame delivers one serialized PTCP frame from a scripted loopback
// peer to the socket under test.
func sendPTCPFrame(t *testing.T, peer *net.UDPConn, u *UDP, body []byte) {
	t.Helper()
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: u.lport}
	if _, err := peer.WriteToUDP((&PTCP{Body: body}).Bytes(), addr); err != nil {
		t.Fatalf("send ptcp frame: %v", err)
	}
}

func TestWaitForPTCPTokenSkipsShortBodies(t *testing.T) {
	u := NewUDP("", 0, false, nil)
	if u.initErr != nil {
		t.Fatalf("udp init: %v", u.initErr)
	}
	defer u.Close()

	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Skipf("udp listen: %v", err)
	}
	defer peer.Close()

	// The exact panic trigger: a 4-byte body (length of the SYNC payload
	// the agent echoes — old guard passed it, [12:4] crashed).
	sendPTCPFrame(t, peer, u, []byte{0x00, 0x03, 0x01, 0x00})
	// A 12-byte body is also unusable ([12:] would yield an empty sign).
	sendPTCPFrame(t, peer, u, make([]byte, 12))

	token := make([]byte, 32)
	for i := range token {
		token[i] = byte(i + 1)
	}
	sendPTCPFrame(t, peer, u, token)

	tr := &Tunnel{}
	p, err := tr.waitForPTCPToken(u, 5*time.Second)
	if err != nil {
		t.Fatalf("waitForPTCPToken: %v", err)
	}
	if len(p.Body) != len(token) {
		t.Fatalf("token body = %d bytes, want %d", len(p.Body), len(token))
	}
	for i, b := range p.Body {
		if b != token[i] {
			t.Fatalf("token body[%d] = %#02x, want %#02x", i, b, token[i])
		}
	}
}

func TestWaitForPTCPTokenTimesOutOnShortBodiesOnly(t *testing.T) {
	u := NewUDP("", 0, false, nil)
	if u.initErr != nil {
		t.Fatalf("udp init: %v", u.initErr)
	}
	defer u.Close()

	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Skipf("udp listen: %v", err)
	}
	defer peer.Close()

	// Only noise: the token never arrives — must surface a timeout error,
	// never panic, and the pure-ACK frame (empty body) must be skipped too.
	sendPTCPFrame(t, peer, u, nil)
	sendPTCPFrame(t, peer, u, []byte{0x0A, 0x00})

	tr := &Tunnel{}
	if _, err := tr.waitForPTCPToken(u, 300*time.Millisecond); err == nil {
		t.Fatalf("waitForPTCPToken: want timeout error, got a body")
	}
}
