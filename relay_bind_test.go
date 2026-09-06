package main

// Regression tests for the app-parity relay data path (capture 2026-09-06,
// spike/capture/dmss-capture2.pcap):
//
//   - realm DATA must never be sent before the BIND's 0x12 CONN ack — the
//     captured app always binds FRESH, receives CONN, and only then pushes
//     DATA (~6 ms apart); wiring the local client before the bind races
//     DATA ahead of the BIND and the device answers with an immediate
//     0x12 DISC (observed live 2026-09-06);
//   - the pre-bound realm pool must stay disabled for noRelayAuth (dmss)
//     profiles: pre-bound realms go stale device-side and their DATA is
//     discarded.

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

// bindScriptPeer wraps a dhTestPeer with a PTCP-aware script: BIND (0x11)
// frames are recorded and held silent until the test releases proceed
// (the peer then answers with a 0x12 CONN for that realm); DATA (0x10)
// frames are recorded and stay unanswered.
type bindScriptPeer struct {
	*dhTestPeer
	proceed chan struct{}
}

func newBindScriptPeer(t *testing.T) *bindScriptPeer {
	t.Helper()
	p := &bindScriptPeer{dhTestPeer: newDHTestPeer(t), proceed: make(chan struct{})}
	p.setRespFn(func(raw string) (string, bool) {
		if !strings.HasPrefix(raw, "PTCP") || len(raw) < 25 {
			return "", false
		}
		switch raw[24] {
		case 0x11: // BIND — wait for the test, then ack with 0x12 CONN.
			<-p.proceed
			realm := binary.BigEndian.Uint32([]byte(raw[28:32]))
			body := make([]byte, 16)
			body[0] = 0x12
			binary.BigEndian.PutUint32(body[4:8], realm)
			copy(body[12:], "CONN")
			return string((&PTCP{Body: body}).Bytes()), true
		case 0x10: // realm DATA — recorded, never answered.
			return "", true
		}
		return "", true
	})
	return p
}

// ptcpBodies returns the recorded PTCP frames' bodies classified by first
// byte (0x11 BIND / 0x10 DATA).
func ptcpBodies(p *dhTestPeer) (binds, datas int) {
	for _, raw := range p.requests() {
		if !strings.HasPrefix(raw, "PTCP") || len(raw) < 25 {
			continue
		}
		switch raw[24] {
		case 0x11:
			binds++
		case 0x10:
			datas++
		}
	}
	return binds, datas
}

func newBindTestTunnel(t *testing.T, prof *appProfile, p *dhTestPeer) *Tunnel {
	t.Helper()
	tt := newTunnel("SN123", prof, 0, "", "", "", false, false, false, 0, specGroup{}, nil)
	u := NewUDP("127.0.0.1", p.port, false, prof)
	t.Cleanup(u.Close)
	tt.primary = u
	// routePTCP (the 0x12 CONN dispatcher) runs inside serve()'s read loops.
	tt.readerWG.Add(1)
	go tt.readLoop(tt.done, u)
	return tt
}

// The ordering regression: with the pre-fix handleBind the local client was
// registered (and its reader goroutine pumping) BEFORE the BIND left the
// socket, so realm DATA could reach the relay ahead of the BIND. The peer
// here never acks until the test says so — any DATA observed before the
// release is exactly that race.
func TestHandleBindGatesDataOnConn(t *testing.T) {
	p := newBindScriptPeer(t)
	prof := *dmssProfile
	tt := newBindTestTunnel(t, &prof, p.dhTestPeer)

	local, remote := net.Pipe()
	t.Cleanup(func() { local.Close(); remote.Close() })

	go tt.handleBind(acceptConn{conn: remote, remotePort: 80})

	// The BIND arrives and is held (no CONN yet).
	deadline := time.Now().Add(2 * time.Second)
	for {
		if binds, _ := ptcpBodies(p.dhTestPeer); binds >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no BIND frame reached the peer")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Client bytes must NOT reach the wire while the realm is unconfirmed.
	go local.Write([]byte("GET /cgi-bin/magicBox.cgi HTTP/1.1\r\n\r\n"))
	time.Sleep(300 * time.Millisecond)
	if _, datas := ptcpBodies(p.dhTestPeer); datas != 0 {
		t.Fatalf("realm DATA left before the 0x12 CONN ack (%d frames) — client must gate on CONN", datas)
	}

	// Release the CONN: the realm activates and the buffered bytes flow.
	close(p.proceed)
	deadline = time.Now().Add(2 * time.Second)
	for {
		_, datas := ptcpBodies(p.dhTestPeer)
		if datas >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no realm DATA after CONN — buffered client bytes never pumped")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The pre-bound realm pool is a liability under the app relay dialect
// (pre-bound realms go stale device-side); noRelayAuth profiles force it
// off regardless of --pool, smartpss keeps the requested level.
func TestNewTunnelPoolDisabledForNoRelayAuth(t *testing.T) {
	dmss := *dmssProfile
	if !dmss.noRelayAuth {
		t.Fatal("dmss profile must set noRelayAuth (app relay dialect: no 0x17/0x19)")
	}
	tt := newTunnel("SN123", &dmss, 0, "", "", "", false, false, false, 50, specGroup{}, nil)
	if tt.poolTarget != 0 {
		t.Fatalf("dmss tunnel must disable the realm pool, got poolTarget=%d", tt.poolTarget)
	}
	sp := *smartpssProfile
	if sp.noRelayAuth {
		t.Fatal("smartpss profile must keep the 0x17/0x19 handshake (upstream dialect)")
	}
	tt2 := newTunnel("SN123", &sp, 0, "", "", "", false, false, false, 50, specGroup{}, nil)
	if tt2.poolTarget != 50 {
		t.Fatalf("smartpss tunnel must keep the requested pool level, got poolTarget=%d", tt2.poolTarget)
	}
}
