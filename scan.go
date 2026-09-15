package main

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"os"
	"sort"
	"strings"
	"time"
)

// scanFlag implements flag.Value and flag.boolFlag so --scan can be used as a boolean
// flag alone (--scan) or with optional port specifications (--scan=80,37777 or positional).
type scanFlag struct {
	enabled bool
	ports   string
}

func (s *scanFlag) String() string {
	if s.ports != "" {
		return s.ports
	}
	if s.enabled {
		return "true"
	}
	return "false"
}

func (s *scanFlag) Set(val string) error {
	s.enabled = true
	if val != "" && val != "true" && val != "false" {
		s.ports = val
	}
	return nil
}

func (s *scanFlag) IsBoolFlag() bool {
	return true
}

// Default top Dahua camera ports to scan if none specified.
var defaultScanPorts = []int{
	21,    // FTP
	22,    // SSH
	23,    // Telnet
	80,    // HTTP Web UI
	443,   // HTTPS Web UI
	554,   // RTSP Video Stream
	1935,  // RTMP
	5000,  // Dahua Mobile / Legacy
	5060,  // SIP (VTO / Doorbell)
	8000,  // Secondary Stream / DVR
	8080,  // Alt HTTP
	8888,  // Alt Web / Debug
	37777, // DVRIP Main Management (SmartPSS, DMSS)
	37778, // DVRIP UDP
	38800, // Discovery / P2P Local
}

func parseScanPortList(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "default" || spec == "top" {
		return defaultScanPorts, nil
	}
	// Support "local:remote" or just "remote"
	if strings.Contains(spec, ":") {
		parts := strings.SplitN(spec, ":", 2)
		spec = parts[1]
	}
	ports, err := parseIntList(spec)
	if err != nil {
		return nil, err
	}
	// Deduplicate and filter valid range [1, 65535]
	seen := make(map[int]bool)
	var out []int
	for _, p := range ports {
		if p >= 1 && p <= 65535 && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Ints(out)
	return out, nil
}

type portScanResult struct {
	port   int
	isOpen bool
}

// scanSinglePort tests whether targetPort is open on the camera through the active P2P data path.
// Dahua P2P semantics:
//   - When camera daemon connects to targetPort successfully, it returns 0x12 CONN.
//   - When the port is closed (RST / ECONNREFUSED), it returns 0x12 DISC.
func (t *Tunnel) scanSinglePort(targetPort int) bool {
	p := t.getPrimary()
	if p == nil {
		return false
	}

	realmID := rand.Uint32()
	wait12 := make(chan scanOutcome, 4)

	t.scanMu.Lock()
	t.scanWait[realmID] = wait12
	t.scanMu.Unlock()

	defer func() {
		t.scanMu.Lock()
		delete(t.scanWait, realmID)
		t.scanMu.Unlock()

		// Send DISC to clean up realm on remote side if it was opened
		p := t.getPrimary()
		if p != nil && !t.useTCPPath {
			discPkt := make([]byte, 16)
			discPkt[0] = 0x12
			binary.BigEndian.PutUint32(discPkt[4:8], realmID)
			copy(discPkt[12:], "DISC")
			p.RequestPTCP(discPkt)
		}
	}()

	bindPkt := make([]byte, 20)
	bindPkt[0] = 0x11
	binary.BigEndian.PutUint32(bindPkt[4:8], realmID)
	binary.BigEndian.PutUint32(bindPkt[12:16], uint32(targetPort))
	bindPkt[16] = 0x7F
	bindPkt[19] = 0x01

	// Up to 2 attempts in case the initial UDP datagram drops on the relay
	for attempt := 0; attempt < 2; attempt++ {
		t.bindReqMu.Lock()
		p = t.getPrimary()
		if p == nil {
			t.bindReqMu.Unlock()
			return false
		}
		p.RequestPTCP(bindPkt)
		time.Sleep(3 * time.Millisecond)
		t.bindReqMu.Unlock()

		select {
		case outcome := <-wait12:
			if outcome == scanOutcomeDisc {
				t.logf("Scan port %d: received DISC (closed)", targetPort)
				return false
			}
			t.logf("Scan port %d: received CONN (open)", targetPort)
			return true
		case <-time.After(1500 * time.Millisecond):
			if attempt == 0 {
				t.logf("Scan port %d: timeout waiting for 0x12, retrying BIND", targetPort)
			}
		case <-t.done:
			return false
		}
	}

	t.logf("Scan port %d: no response after retries (closed/unreachable)", targetPort)
	return false
}

// runPortScan performs sequential 1-port-per-4-seconds scanning to prevent relay/device rate limiting.
func runPortScan(serial string, prof *appProfile, ports []int, dtype int, username, password, randsalt string, debug, logRetries, tcpRelay bool) {
	// Dummy spec to initialize tunnel data path
	g := specGroup{idxs: []int{0}, specs: []PortSpec{{Local: 0, Remote: 37777}}}
	t := newTunnel(serial, prof, dtype, username, password, randsalt, debug, logRetries, tcpRelay, 0, false, g, nil)

	cp := NewConnectProgress(os.Stdout, serial)
	t.progress = cp

	if err := t.handshake(); err != nil {
		cp.Fail(err.Error())
		return
	}
	defer t.close()
	cp.Done("P2P tunnel established")

	// Start reader and heartbeat loops so PTCP frames flow and get routed
	done := t.done
	if t.useTCPPath {
		t.readerWG.Add(2)
		go t.touReadLoop(done)
		go t.touHeartbeatLoop(done)
	} else {
		t.readerWG.Add(3)
		go t.readLoop(done, t.deviceRemote)
		go t.readLoop(done, t.mainRemote)
		go t.heartbeatLoop(done)
	}

	results := make([]portScanResult, len(ports))
	for i, p := range ports {
		results[i].port = p
	}

	sp := NewScanProgress(os.Stdout, serial, len(ports))

	for i, targetPort := range ports {
		sp.UpdateScanning(i, targetPort)

		isOpen := t.scanSinglePort(targetPort)
		results[i].isOpen = isOpen

		// 4-second rate-limit pacing between consecutive ports
		if i < len(ports)-1 {
			stateStr := "CLOSED"
			if isOpen {
				stateStr = "OPEN"
			}
			for sec := 4; sec > 0; sec-- {
				sp.UpdateWaiting(i+1, targetPort, stateStr, sec)
				select {
				case <-time.After(1 * time.Second):
				case <-t.done:
					return
				}
			}
		} else {
			sp.Update(len(ports), targetPort)
		}
	}

	sp.Done()

	// Print results exactly in requested format:
	// SN: sn
	// port   |  state
	// 80     |  CLOSED
	// 37777  |  OPEN
	fmt.Printf("\nSN: %s\n", serial)
	fmt.Println("port   |  state")
	for _, r := range results {
		state := "CLOSED"
		if r.isOpen {
			state = "OPEN"
		}
		fmt.Printf("%-6d |  %s\n", r.port, state)
	}
	fmt.Println()
}
