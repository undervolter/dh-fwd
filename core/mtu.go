package core

import (
	"bytes"
	"fmt"
	"net"
	"strconv"
	"time"
)

var GlobalMTU int

const (
	// dataSegmentMax matches Dahua's CProxySession default MTU (0x18012C71C).
	dataSegmentMax = 1280

	// wireOverheadIPv4 is the total encapsulation overhead for a PTCP payload over IPv4:
	// IPv4 header (20B) + UDP header (8B) + PTCP header (24B) + PTCPPayload header (12B) = 64B.
	wireOverheadIPv4 = 64

	// wireOverheadIPv6 is the total overhead over IPv6 (40B IPv6 + 8B UDP + 24B PTCP + 12B Payload = 84B).
	wireOverheadIPv6 = 84

	// minSegmentMax is the lowest allowed segment payload to prevent pathological fragmentation.
	minSegmentMax = 256
)

// probePathMTU performs active UDP Path MTU Discovery against the Dahua dispatcher.
// It steps through standard network MTU thresholds (1500, 1420, 1280, 1200)
// using padded DHGET /probe/p2psrv requests with Don't Fragment (DF) flag set.
func probePathMTU(serverHost string, serverPort int, timeout time.Duration) int {
	if serverHost == "" {
		serverHost = MAIN_SERVER
	}
	if serverPort <= 0 {
		serverPort = MAIN_PORT
	}

	candidates := []int{1500, 1420, 1280, 1200}
	for _, mtu := range candidates {
		payloadLen := mtu - 28
		base := "DHGET /probe/p2psrv HTTP/1.1\r\nCSeq: 1\r\nX-Pad: "
		padLen := payloadLen - len(base) - 4
		if padLen < 0 {
			continue
		}
		pad := make([]byte, padLen)
		for i := range pad {
			pad[i] = 'A'
		}
		req := []byte(base + string(pad) + "\r\n\r\n")

		raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(serverHost, strconv.Itoa(serverPort)))
		if err != nil {
			return 0
		}
		conn, err := net.DialUDP("udp", nil, raddr)
		if err != nil {
			continue
		}

		setSocketDF(conn)
		_ = conn.SetDeadline(time.Now().Add(timeout))

		_, err = conn.Write(req)
		if err != nil {
			conn.Close()
			continue
		}

		rx := make([]byte, 512)
		n, err := conn.Read(rx)
		conn.Close()
		if err == nil && n > 0 && bytes.Contains(rx[:n], []byte("200 OK")) {
			return mtu
		}
	}
	return 0
}

// detectInterfaceMTU finds the MTU of the local network interface routing to remoteHost.
func detectInterfaceMTU(remoteHost string) int {
	if remoteHost != "" {
		conn, err := net.Dial("udp", net.JoinHostPort(remoteHost, "80"))
		if err == nil {
			defer conn.Close()
			if udpAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
				localIP := udpAddr.IP
				if ifaces, err := net.Interfaces(); err == nil {
					for _, iface := range ifaces {
						if iface.Flags&net.FlagUp == 0 {
							continue
						}
						addrs, err := iface.Addrs()
						if err != nil {
							continue
						}
						for _, a := range addrs {
							var ip net.IP
							switch v := a.(type) {
							case *net.IPNet:
								ip = v.IP
							case *net.IPAddr:
								ip = v.IP
							}
							if ip != nil && ip.Equal(localIP) && iface.MTU > 0 {
								return iface.MTU
							}
						}
					}
				}
			}
		}
	}

	if ifaces, err := net.Interfaces(); err == nil {
		minMTU := 0
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			if iface.MTU > 0 && iface.MTU < 1500 {
				if minMTU == 0 || iface.MTU < minMTU {
					minMTU = iface.MTU
				}
			}
		}
		if minMTU > 0 {
			return minMTU
		}
	}
	return 0
}

// resolveSegmentMax computes the wire-safe PTCP segment payload size:
func resolveSegmentMax(remoteHost string, userMTU int, isIPv6 bool, logf func(string, ...any)) int {
	overhead := wireOverheadIPv4
	if isIPv6 {
		overhead = wireOverheadIPv6
	}

	if userMTU > 0 {
		var seg int
		if userMTU >= 576 {
			seg = userMTU - overhead
		} else {
			seg = userMTU
		}
		if seg > dataSegmentMax {
			seg = dataSegmentMax
		}
		if seg < minSegmentMax {
			seg = minSegmentMax
		}
		if logf != nil {
			logf("MTU: forced %d -> data segment %d bytes (overhead=%d)", userMTU, seg, overhead)
		}
		return seg
	}

	// KISS: Dahua CProxySession (0x180024480) hardcodes 1280.
	// Avoid startup probe latency / interface quirks; live PMTUD is kept in RunMTUTest (--test-mtu).
	if logf != nil {
		logf("MTU: default data segment %d bytes (Dahua CProxySession parity)", dataSegmentMax)
	}
	return dataSegmentMax
}

// RunMTUTest executes a verbose diagnostic test and prints the live results.
func RunMTUTest(remoteHost string) {
	if remoteHost == "" {
		remoteHost = MAIN_SERVER
	}
	fmt.Printf("[*] Detecting Local Network Interfaces MTU...\n")
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			fmt.Printf("    - %-32s MTU: %d\n", iface.Name, iface.MTU)
		}
	}

	detected := detectInterfaceMTU(remoteHost)
	fmt.Printf("[*] Active Interface MTU for %s: %d\n", remoteHost, detected)
	fmt.Printf("[*] Running Active UDP PMTUD Probes against %s:%d (DF bit set)...\n", remoteHost, MAIN_PORT)

	candidates := []int{1500, 1420, 1280, 1200}
	best := 0
	for _, mtu := range candidates {
		payloadLen := mtu - 28
		base := "DHGET /probe/p2psrv HTTP/1.1\r\nCSeq: 1\r\nX-Pad: "
		padLen := payloadLen - len(base) - 4
		if padLen < 0 {
			continue
		}
		pad := make([]byte, padLen)
		for i := range pad {
			pad[i] = 'A'
		}
		req := []byte(base + string(pad) + "\r\n\r\n")

		raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(remoteHost, strconv.Itoa(MAIN_PORT)))
		if err != nil {
			fmt.Printf("    [-] MTU %d: resolve error: %v\n", mtu, err)
			continue
		}
		t0 := time.Now()
		conn, err := net.DialUDP("udp", nil, raddr)
		if err != nil {
			fmt.Printf("    [-] MTU %d: dial error: %v\n", mtu, err)
			continue
		}
		setSocketDF(conn)
		_ = conn.SetDeadline(time.Now().Add(1200 * time.Millisecond))
		_, err = conn.Write(req)
		if err != nil {
			conn.Close()
			fmt.Printf("    [-] MTU %d: FAILED (%v)\n", mtu, err)
			continue
		}
		rx := make([]byte, 512)
		n, err := conn.Read(rx)
		conn.Close()
		rtt := time.Since(t0)
		if err == nil && n > 0 && bytes.Contains(rx[:n], []byte("200 OK")) {
			fmt.Printf("    [+] MTU %d: PASSED (200 OK received in %v)\n", mtu, rtt)
			if best == 0 {
				best = mtu
			}
		} else {
			fmt.Printf("    [-] MTU %d: FAILED (timed out or dropped by route)\n", mtu)
		}
	}

	seg := resolveSegmentMax(remoteHost, best, false, nil)
	fmt.Println()
	if best > 0 {
		fmt.Printf("[+] Verdict: Real Path MTU is %d. Optimal PTCP chunk size: %d bytes\n", best, seg)
	} else {
		fmt.Printf("[-] Verdict: UDP probes failed (blocked by firewall/DPI). Use -R / --tcp-relay\n")
	}
}
