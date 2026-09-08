package main

import (
	"bufio"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// Scripted local TCP-relay agent for dialTCPRelay, modeled on dhTestPeer
// (verify_test.go): the agent records the raw bind request, answers 200 OK,
// and completes the TOU handshake (SYN → ACK), so assertions run on the
// actual wire bytes of the bind path.

type tcpRelayAgent struct {
	ln     net.Listener
	mu     sync.Mutex
	bind   string // full bind request: head + body
	synSes uint32 // session from the client's SYN
}

func newTCPRelayAgent(t *testing.T) *tcpRelayAgent {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("tcp listen: %v", err)
	}
	a := &tcpRelayAgent{ln: ln}
	go a.serve()
	t.Cleanup(func() { ln.Close() })
	return a
}

func (a *tcpRelayAgent) addr() (string, int) {
	host, portS, _ := net.SplitHostPort(a.ln.Addr().String())
	port, _ := strconv.Atoi(portS)
	return host, port
}

func (a *tcpRelayAgent) recorded() (string, uint32) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.bind, a.synSes
}

func (a *tcpRelayAgent) serve() {
	conn, err := a.ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()

	// Bind request: head, then the Content-Length body.
	rd := bufio.NewReader(conn)
	head, err := readHTTPHeader(rd)
	if err != nil {
		return
	}
	bodyLen := 0
	for _, line := range strings.Split(head, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "content-length:") {
			bodyLen, _ = strconv.Atoi(strings.TrimSpace(line[len("content-length:"):]))
		}
	}
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(rd, body); err != nil {
		return
	}
	a.mu.Lock()
	a.bind = head + string(body)
	a.mu.Unlock()

	// Bind answer with a short body (keeps the TOU stream aligned, as the
	// real agent's answer does).
	conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"))

	// TOU handshake: read the client's SYN, ACK its session.
	syn := make([]byte, touSynSize)
	if _, err := io.ReadFull(rd, syn); err != nil {
		return
	}
	typ, session, _, _, err := parseTouPacket(syn)
	if err != nil || typ != touTypeSyn {
		return
	}
	a.mu.Lock()
	a.synSes = session
	a.mu.Unlock()
	conn.Write(touBuildAck(session, 0))

	// Hold the channel open until the test tears the client down.
	buf := make([]byte, 512)
	for {
		if _, err := conn.Read(buf); err != nil {
			return
		}
	}
}

// readHTTPHeader reads one HTTP request head, up to and including the blank
// CRLF line (the request-side counterpart of tcp_relay.go's
// readHTTPResponse).
func readHTTPHeader(rd *bufio.Reader) (string, error) {
	var sb strings.Builder
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			return sb.String(), err
		}
		sb.WriteString(line)
		if line == "\r\n" {
			return sb.String(), nil
		}
	}
}

// [M6] The TCP-relay bind must speak the PROFILE's post verb — DHPOST for
// smartpss (byte-for-byte legacy), NFPOST for dmss — with the profile's WSSE
// pair, and still complete the SYN/ACK handshake on the same socket.
func TestDialTCPRelayBindRequestShape(t *testing.T) {
	logf := func(string, ...any) {}

	for _, prof := range []*appProfile{smartpssProfile, dmssProfile} {
		t.Run(prof.name, func(t *testing.T) {
			agent := newTCPRelayAgent(t)
			host, port := agent.addr()

			ch, err := dialTCPRelay(prof, host, port, "T0KEN", false, logf)
			if err != nil {
				t.Fatalf("dialTCPRelay(%s): %v", prof.name, err)
			}
			defer ch.close()

			bind, synSes := agent.recorded()

			// Status line: profile post verb + the fixed bind path.
			wantLine := prof.verbPost + " /tcprelay/client-bind HTTP/1.1\r\n"
			if !strings.HasPrefix(bind, wantLine) {
				t.Fatalf("%s bind does not start with %q:\n%s", prof.name, wantLine, bind)
			}

			// WSSE auth carries the profile's own pair.
			user := regexp.MustCompile(`Username="([^"]+)"`).FindStringSubmatch(bind)
			if user == nil || user[1] != prof.wsseUser {
				t.Fatalf("%s bind Username = %v, want %q:\n%s", prof.name, user, prof.wsseUser, bind)
			}
			for _, frag := range []string{
				"Authorization: WSSE profile=\"UsernameToken\"\r\n",
				"PasswordDigest=\"", "Nonce=\"", "Created=\"",
			} {
				if !strings.Contains(bind, frag) {
					t.Fatalf("%s bind missing %q:\n%s", prof.name, frag, bind)
				}
			}

			// Token body with a matching Content-Length.
			const wantBody = `{"Token":"T0KEN"}`
			if !strings.HasSuffix(bind, "\r\n\r\n"+wantBody) {
				t.Fatalf("%s bind body missing %q:\n%s", prof.name, wantBody, bind)
			}
			if !strings.Contains(bind, "Content-Length: "+strconv.Itoa(len(wantBody))+"\r\n") {
				t.Fatalf("%s bind Content-Length wrong:\n%s", prof.name, bind)
			}

			// Dialect headers travel the TCP path too (dmss only).
			if prof.name == "dmss" && !strings.Contains(bind, "X-ToUType: "+prof.toUType+"\r\n") {
				t.Fatalf("dmss bind missing X-ToUType:\n%s", bind)
			}

			// The channel is the one the agent ACKed (SYN session echoed).
			if ch.localSession != synSes {
				t.Fatalf("SYN session %#010x != agent-ACKed %#010x", ch.localSession, synSes)
			}
		})
	}
}
