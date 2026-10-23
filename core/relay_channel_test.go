package core

import (
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWaitRelayChannelAckImmediate(t *testing.T) {
	p := newDHTestPeer(t)
	prof := *smartpssProfile
	prof.mainServer = "127.0.0.1"
	prof.mainPort = p.port

	g := specGroup{idxs: []int{0}, specs: []PortSpec{{Local: 0, Remote: 554}}}
	tt := newTunnel("SN123", &prof, 0, "", "", "", false, false, false, 0, false, g, nil)
	defer tt.close()

	origInterval, origRetrans := relayChannelRetransInterval, relayChannelMaxRetransmits
	relayChannelRetransInterval = 50 * time.Millisecond
	relayChannelMaxRetransmits = 2
	defer func() {
		relayChannelRetransInterval, relayChannelMaxRetransmits = origInterval, origRetrans
	}()

	mainRemote := NewUDP("127.0.0.1", p.port, false, &prof)
	defer mainRemote.Close()

	err := tt.waitRelayChannelAck(mainRemote, "127.0.0.1", p.port, "")
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}

	reqs := dhRequests(p)
	relayCount := 0
	for _, req := range reqs {
		if strings.Contains(req, "/relay-channel") {
			relayCount++
		}
	}
	if relayCount != 1 {
		t.Fatalf("expected 1 relay-channel request, got %d", relayCount)
	}
}

func TestWaitRelayChannelAckRetransmitOnTimeout(t *testing.T) {
	p := newDHTestPeer(t)
	prof := *smartpssProfile
	prof.mainServer = "127.0.0.1"
	prof.mainPort = p.port

	g := specGroup{idxs: []int{0}, specs: []PortSpec{{Local: 0, Remote: 554}}}
	tt := newTunnel("SN123", &prof, 0, "", "", "", false, false, false, 0, false, g, nil)
	defer tt.close()

	origInterval, origRetrans := relayChannelRetransInterval, relayChannelMaxRetransmits
	relayChannelRetransInterval = 60 * time.Millisecond
	relayChannelMaxRetransmits = 3
	defer func() {
		relayChannelRetransInterval, relayChannelMaxRetransmits = origInterval, origRetrans
	}()

	var attempts int32
	p.setRespFn(func(raw string) (string, bool) {
		if strings.Contains(raw, "/relay-channel") {
			cnt := atomic.AddInt32(&attempts, 1)
			if cnt == 1 {
				// Drop the first attempt
				return "", true
			}
			// Succeed on 2nd attempt
			return "HTTP/1.1 200 OK\r\n\r\n", true
		}
		return "", false
	})

	mainRemote := NewUDP("127.0.0.1", p.port, false, &prof)
	defer mainRemote.Close()

	err := tt.waitRelayChannelAck(mainRemote, "127.0.0.1", p.port, "")
	if err != nil {
		t.Fatalf("expected success on retransmit, got error: %v", err)
	}

	if got := atomic.LoadInt32(&attempts); got != 2 {
		t.Fatalf("expected 2 attempts before success, got %d", got)
	}

	// Verify that CSeq remained the same across the retransmission
	reqs := dhRequests(p)
	var cseqs []int
	for _, req := range reqs {
		if strings.Contains(req, "/relay-channel") {
			cseqs = append(cseqs, cseqOf(t, req))
		}
	}
	if len(cseqs) != 2 {
		t.Fatalf("expected 2 relay-channel requests recorded, got %d", len(cseqs))
	}
	if cseqs[0] != cseqs[1] {
		t.Fatalf("CSeq changed across retransmit: first=%d second=%d", cseqs[0], cseqs[1])
	}
}

func TestWaitRelayChannelAckExhausted(t *testing.T) {
	p := newDHTestPeer(t)
	prof := *smartpssProfile
	prof.mainServer = "127.0.0.1"
	prof.mainPort = p.port

	g := specGroup{idxs: []int{0}, specs: []PortSpec{{Local: 0, Remote: 554}}}
	tt := newTunnel("SN123", &prof, 0, "", "", "", false, false, false, 0, false, g, nil)
	defer tt.close()

	origInterval, origRetrans := relayChannelRetransInterval, relayChannelMaxRetransmits
	relayChannelRetransInterval = 30 * time.Millisecond
	relayChannelMaxRetransmits = 2
	defer func() {
		relayChannelRetransInterval, relayChannelMaxRetransmits = origInterval, origRetrans
	}()

	var attempts int32
	p.setRespFn(func(raw string) (string, bool) {
		if strings.Contains(raw, "/relay-channel") {
			atomic.AddInt32(&attempts, 1)
			return "", true // Drop all
		}
		return "", false
	})

	mainRemote := NewUDP("127.0.0.1", p.port, false, &prof)
	defer mainRemote.Close()

	err := tt.waitRelayChannelAck(mainRemote, "127.0.0.1", p.port, "")
	if err == nil {
		t.Fatal("expected error on exhausted retries, got nil")
	}
	if !strings.Contains(err.Error(), "relay-channel read:") {
		t.Fatalf("unexpected error message: %v", err)
	}

	// initial attempt + 2 retransmits = 3 attempts total
	if got := atomic.LoadInt32(&attempts); got != 3 {
		t.Fatalf("expected 3 attempts (1 + 2 retries), got %d", got)
	}
}


func TestWaitRelayChannelAckIgnores100Trying(t *testing.T) {
	p := newDHTestPeer(t)
	prof := *smartpssProfile
	prof.mainServer = "127.0.0.1"
	prof.mainPort = p.port

	g := specGroup{idxs: []int{0}, specs: []PortSpec{{Local: 0, Remote: 554}}}
	tt := newTunnel("SN123", &prof, 0, "", "", "", false, false, false, 0, false, g, nil)
	defer tt.close()

	origFirst, origInterval, origRetrans := relayChannelFirstInterval, relayChannelRetransInterval, relayChannelMaxRetransmits
	relayChannelFirstInterval = 300 * time.Millisecond
	relayChannelRetransInterval = 300 * time.Millisecond
	relayChannelMaxRetransmits = 2
	defer func() {
		relayChannelFirstInterval, relayChannelRetransInterval, relayChannelMaxRetransmits = origFirst, origInterval, origRetrans
	}()

	mainRemote := NewUDP("127.0.0.1", p.port, false, &prof)
	defer mainRemote.Close()

	var phase int32
	p.setRespFn(func(raw string) (string, bool) {
		if strings.Contains(raw, "/relay-channel") {
			cnt := atomic.AddInt32(&phase, 1)
			if cnt == 1 {
				// Cloud sends 100 Trying first while waking up remote camera
				// Send 100 Trying now, and schedule 200 OK 30ms later to mainRemote
				go func() {
					time.Sleep(30 * time.Millisecond)
					target := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: mainRemote.lport}
					p.conn.WriteToUDP([]byte("HTTP/1.1 200 OK\r\n\r\n"), target)
				}()
				return "HTTP/1.1 100 Trying\r\n\r\n", true
			}
			return "HTTP/1.1 200 OK\r\n\r\n", true
		}
		return "", false
	})

	err := tt.waitRelayChannelAck(mainRemote, "127.0.0.1", p.port, "")
	if err != nil {
		t.Fatalf("expected success after 100 Trying -> 200 OK, got error: %v", err)
	}

	reqs := dhRequests(p)
	relayCount := 0
	for _, req := range reqs {
		if strings.Contains(req, "/relay-channel") {
			relayCount++
		}
	}
	// Should NOT retransmit since 200 OK arrived within the same attempt window
	if relayCount != 1 {
		t.Fatalf("expected exactly 1 relay-channel request, got %d", relayCount)
	}
}
