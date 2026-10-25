package core

// relay_resilience.go — resilience mechanisms for the UDP relay path:
// 1. Dispatcher concurrency limiting via semaphore.
// 2. Per-host backoff to skip unresponsive relay dispatchers.
// 3. Zombie watchdog: detects when a relay path stops forwarding data back
//    and triggers tunnel reconnection.

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// isTransportDead reports whether a ReadPTCP error means the underlying
// socket is gone (as opposed to "the datagram wasn't a PTCP frame").
// Parse errors from ParsePTCP and short reads are payload problems — the
// readLoop treats them as ignorable noise. Everything else (closed conn,
// ICMP-induced reset, out-of-fd) is terminal.
func isTransportDead(err error) bool {
	if err == nil {
		return false
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return false
	}
	// ParsePTCP / ParsePTCPPayload / tou framing errors are content errors.
	msg := err.Error()
	for _, marker := range []string{
		"packet too short",
		"invalid magic",
		"invalid padding",
		"invalid length",
		"invalid tou message",
	} {
		if strings.Contains(msg, marker) {
			return false
		}
	}
	return true
}

var errZombieRelay = errors.New("relay zombie: bind acks pass but no DATA comes back")

// RelayAllocLimit bounds concurrent /relay/agent allocations.
var RelayAllocLimit = 6

// Relay timeouts and retries.
var (
	relayAgentAllocTimeout = 4 * time.Second
	relayDispatchBase      = 3 * time.Second
	relayDispatchMax       = 15 * time.Second
	relayStartRetries      = 3
	relayStartAuthRetries  = 3
	relayStartRetransDelay = 1200 * time.Millisecond
	zombieRelayTimeout     = 12 * time.Second
	zombieScanEvery        = 3 * time.Second
)

var (
	relaySemOnce  sync.Once
	relayAllocSem chan struct{}
)

func relayAllocSlot() chan struct{} {
	relaySemOnce.Do(func() { relayAllocSem = make(chan struct{}, RelayAllocLimit) })
	return relayAllocSem
}

// relayDispatchState tracks known relay dispatchers and backoff penalties.
type relayDispatchState struct {
	mu       sync.Mutex
	known    []string
	failures map[string]int
	until    map[string]time.Time
}

var relayDispatch = &relayDispatchState{
	failures: map[string]int{},
	until:    map[string]time.Time{},
}

func (s *relayDispatchState) remember(hostport string) {
	if hostport == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, h := range s.known {
		if h == hostport {
			return
		}
	}
	s.known = append(s.known, hostport)
	if len(s.known) > 8 {
		s.known = s.known[1:]
	}
}

func (s *relayDispatchState) penalize(hostport string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.failures[hostport] + 1
	s.failures[hostport] = n
	d := relayDispatchBase << (n - 1)
	if d > relayDispatchMax || d <= 0 {
		d = relayDispatchMax
	}
	s.until[hostport] = time.Now().Add(d)
}

func (s *relayDispatchState) forgive(hostport string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.failures, hostport)
	delete(s.until, hostport)
}

func (s *relayDispatchState) backoffLeft(hostport string) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d, ok := s.until[hostport]; ok {
		return time.Until(d)
	}
	return 0
}

// nextTo returns an alternate dispatcher candidate.
func (s *relayDispatchState) nextTo(current string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, h := range s.known {
		if h == current {
			continue
		}
		if d, ok := s.until[h]; ok && time.Now().Before(d) {
			continue
		}
		return h
	}
	return ""
}

// allocRelayAgent requests a relay agent allocation from the cloud dispatcher.
func (t *Tunnel) allocRelayAgent(mainRemote *UDP, dispatcher string) (host string, port int, token string, ok bool) {
	relayAllocSlot()
	select {
	case relayAllocSem <- struct{}{}:
		defer func() { <-relayAllocSem }()
	case <-t.done:
		return "", 0, "", false
	}

	candidates := []string{dispatcher}
	if alt := relayDispatch.nextTo(dispatcher); alt != "" {
		candidates = append(candidates, alt)
	}

	for i, hp := range candidates {
		parts := strings.SplitN(hp, ":", 2)
		if len(parts) != 2 || parts[0] == "" {
			continue
		}
		cport, cportOK := strconv.Atoi(parts[1])
		if cportOK != nil {
			continue
		}
		if left := relayDispatch.backoffLeft(hp); left > 0 {
			if i < len(candidates)-1 {
				continue
			}
			if left > 2*time.Second {
				left = 2 * time.Second
			}
			select {
			case <-time.After(left):
			case <-t.done:
				return "", 0, "", false
			}
		}

		mainRemote.SetRemote(parts[0], cport)
		mainRemote.RequestEx("/relay/agent", "", true, false, reqOpts{})
		res, err := mainRemote.Read(true, relayAgentAllocTimeout)
		if err != nil || res == nil || res.Body["body/Token"] == "" {
			t.logf("relay agent alloc silent on %s (%v) — host backoff, next dispatcher", hp, err)
			relayDispatch.penalize(hp)
			continue
		}
		relayDispatch.forgive(hp)
		agent := strings.SplitN(res.Body["body/Agent"], ":", 2)
		if len(agent) != 2 || agent[0] == "" {
			relayDispatch.penalize(hp)
			continue
		}
		port, _ = strconv.Atoi(agent[1])
		return agent[0], port, res.Body["body/Token"], true
	}
	return "", 0, "", false
}

// startRelayAgent runs /relay/start on behalf of the client.
// P2PDll parity:
//   - Body carries Client = "<bindIP>:<lport>" (sub_18004D420) instead of literal ":0";
//   - 200 finishes start; 401 re-authenticates with fresh crypto up to relayStartAuthRetries (3);
//   - Other codes >=400 abort agent start;
//   - Advertised <Time> budget is logged.
func (t *Tunnel) startRelayAgent(mainRemote *UDP, agentHost string, agentPort int, agentToken string) {
	mainRemote.SetRemote(agentHost, agentPort)
	body := fmt.Sprintf("<body><Client>%s:%d</Client></body>", mainRemote.bindIP, mainRemote.lport)
	auth401 := 0
	for i := 0; i < relayStartRetries+relayStartAuthRetries; i++ {
		mainRemote.RequestEx("/relay/start/"+agentToken, body, true, false, reqOpts{})
		res, err := mainRemote.Read(true, relayStartRetransDelay)
		if err != nil || res == nil {
			continue
		}
		switch {
		case res.Code == 200:
			if v := res.Body["body/Time"]; v != "" {
				t.logf("relay agent session Time=%ss (keepalive budget)", v)
			}
			return
		case res.Code == 401:
			maybeUpdateTimeOffset(res, t.logf)
			auth401++
			if auth401 > relayStartAuthRetries {
				t.logf("relay agent start: 401 auth fail over %d times — giving up", relayStartAuthRetries)
				return
			}
			t.logf("relay agent start: 401 (WSSE rejected) — re-auth %d/%d with fresh crypto", auth401, relayStartAuthRetries)
		default:
			t.logf("relay agent start: unexpected code %d %s — giving up", res.Code, res.Status)
			return
		}
	}
}

// zombieWatchdog monitors data-path liveness on relay connections:
// if local clients upload data but remote peer returns 0 bytes for zombieRelayTimeout,
// marks the relay as a zombie and triggers tunnel reconnection.
func (t *Tunnel) zombieWatchdog(done chan struct{}) {
	defer t.readerWG.Done()
	tick := time.NewTicker(zombieScanEvery)
	defer tick.Stop()
	for {
		select {
		case <-done:
			return
		case <-tick.C:
		}
		now := time.Now()
		var (
			rid    uint32
			port   int
			up     uint64
			age    time.Duration
			zombie bool
		)
		// If we are on direct P2P path (deviceRemote), zombie watchdog is disabled!
		// Direct P2P has normal TCP retransmits and heartbeat; don't kill tunnels on long-polling HTTP requests.
		p := t.getPrimary()
		if p != nil && p == t.deviceRemote {
			continue
		}

		t.clientsMu.Lock()
		var totalDown uint64
		for _, c := range t.clients {
			totalDown += atomic.LoadUint64(&c.dataDown)
		}
		// Only declare zombie if the entire relay path has delivered ZERO bytes back to all clients
		if totalDown == 0 {
			for id, c := range t.clients {
				up = atomic.LoadUint64(&c.dataUp)
				down := atomic.LoadUint64(&c.dataDown)
				if up == 0 || down > 0 {
					continue
				}
				if a := now.Sub(c.created); a > zombieRelayTimeout {
					rid, port, age, zombie = id, c.remotePort, a, true
					break
				}
			}
		}
		t.clientsMu.Unlock()
		if zombie {
			t.logf("zombie data path: realm=%#010x port=%d sent %d bytes, 0 back for %.0fs (relay deaf) — fail for retry",
				rid, port, up, age.Seconds())
			t.forceAppRelay = true
			t.fail(errZombieRelay)
			return
		}
	}
}
