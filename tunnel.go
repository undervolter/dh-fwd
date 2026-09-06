package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	BIND_TIMEOUT   = 10 * time.Second
	RETRY_ATTEMPTS = 3
	RETRY_DELAY    = 2 * time.Second
	CSEQ_BASE      = 100
	CSEQ_STEP      = 1000
)

var (
	HEARTBEAT_TIMEOUT  = 10 * time.Second
	RELAY_READ_TIMEOUT = 15 * time.Second
)

// Bounded reads for the best-effort relay-dispatcher exchange
// (relayAgentOptional profiles only — see profile.go). The dispatcher handed
// out by /online/relay can be dead (live 2026-09-06: the Dolynk relay
// dispatcher at 46.243.143.136:8900 answered /relay/agent with silence,
// 17 s × 3), and the DMSS app never allocates the agent at all, so both
// reads get a short ceiling instead of RELAY_READ_TIMEOUT. Vars like
// localChannelAckTimeout so tests can shrink them.
var (
	relayLookupTimeout = 3 * time.Second
	relayAgentTimeout  = 3 * time.Second
)

var errDeviceNotFound = errors.New("device response: code=404 Not Found")

var notFoundPrinted sync.Once

func deviceNotFound(serial string) {
	notFoundPrinted.Do(func() {
		fmt.Printf("%s doesn't exist or turned off.\n", serial)
	})
}

func isNotFound(reason string) bool {
	return reason == errDeviceNotFound.Error()
}

var ptcpHeartbeat = []byte{
	0x13, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
}

type PortSpec struct {
	Local  int
	Remote int
}

type Client struct {
	conn          net.Conn
	lastKeepalive time.Time
	cseq          int
	remotePort    int

	// Downstream coalescing: the device streams 1280-byte DATA frames;
	// writing each to the browser as a separate TCP segment makes chatty
	// protocols (HTTP) crawl while bulk video hides the cost.
	flushMu    sync.Mutex
	pending    []byte
	flushTimer *time.Timer
}

const (
	coalesceDelay = 2 * time.Millisecond
	coalesceMax   = 16 * 1024
)

// writeData buffers a downstream fragment and flushes to the client socket
// either when the batch fills or after coalesceDelay elapses.
func (c *Client) writeData(b []byte) {
	c.flushMu.Lock()
	c.pending = append(c.pending, b...)
	if len(c.pending) >= coalesceMax {
		out := c.pending
		c.pending = nil
		if c.flushTimer != nil {
			c.flushTimer.Stop()
			c.flushTimer = nil
		}
		c.flushMu.Unlock()
		c.conn.Write(out)
		return
	}
	if c.flushTimer == nil {
		c.flushTimer = time.AfterFunc(coalesceDelay, c.flushNow)
	}
	c.flushMu.Unlock()
}

// flushNow drains the pending batch (timer callback or forced).
func (c *Client) flushNow() {
	c.flushMu.Lock()
	out := c.pending
	c.pending = nil
	c.flushTimer = nil
	c.flushMu.Unlock()
	if len(out) > 0 {
		c.conn.Write(out)
	}
}

type acceptConn struct {
	conn       net.Conn
	remotePort int
}

type specGroup struct {
	idxs  []int
	specs []PortSpec
}

// Tunnel owns one connection cycle to a device: cloud handshake, NAT punch,
// PTCP session, and the local TCP listeners multiplexed over it.
type Tunnel struct {
	serial, username, password, randsalt string
	chanKey                              []byte // Type-1 channel key, for the post-establishment local-channel step
	dtype                                int
	profile                              *appProfile
	debug                                bool
	logRetries                           bool
	useTCP                               bool // force TCP-relay data path

	specs    []PortSpec
	specIdx  []int
	reg      *PortRegistry
	ui       *UI
	progress *ConnectProgress // non-nil only in single-port mode

	deviceRemote *UDP
	mainRemote   *UDP
	primary      *UDP // data path: deviceRemote (direct) or mainRemote (relay)
	useTCPPath   bool // active data path is the TCP relay channel
	tou          *touChannel
	listeners    []net.Listener
	clients      map[uint32]*Client
	clientsMu    sync.Mutex
	acceptCh     chan acceptConn
	done         chan struct{}
	cseqCounter  int

	readerWG  sync.WaitGroup // readLoop + heartbeatLoop goroutines
	bindMu    sync.Mutex
	bindWait  map[uint32]chan struct{}
	bindReqMu sync.Mutex // serializes BIND requests
	socksMu   sync.Mutex
	errMu     sync.Mutex
	failErr   error

	// Realm pool: pre-bound realms per remote port. The camera's web server
	// closes HTTP connections, so browsers reconnect per request; a pooled
	// pre-bound realm removes the BIND round-trip from the critical path.
	// A keeper goroutine maintains the fixed level; in-flight binds are
	// tracked so refills never overshoot.
	poolMu     sync.Mutex
	pools      map[int]*poolState
	poolTarget int
}

// poolState is the per-port pool. All fields guarded by poolMu.
type poolState struct {
	queue    []uint32
	inflight int
}

func newTunnel(serial string, prof *appProfile, dtype int, username, password, randsalt string, debug, logRetries bool, forceTCP bool, poolSize int, g specGroup, reg *PortRegistry) *Tunnel {
	// The app relay dialect binds each realm FRESH, seconds before use
	// (capture: BIND → 0x12 CONN → DATA, ~6 ms apart). Pre-bound realms go
	// stale device-side and their DATA is discarded, so pooling is disabled
	// for noRelayAuth profiles regardless of --pool.
	if prof != nil && prof.noRelayAuth && poolSize > 0 {
		poolSize = 0
	}
	t := &Tunnel{
		serial:      serial,
		dtype:       dtype,
		profile:     prof,
		username:    username,
		password:    password,
		randsalt:    randsalt,
		debug:       debug,
		logRetries:  logRetries,
		useTCP:      forceTCP,
		poolTarget:  poolSize,
		specs:       g.specs,
		specIdx:     g.idxs,
		reg:         reg,
		cseqCounter: CSEQ_BASE,
	}
	if reg != nil {
		t.ui = reg.ui
	}
	t.reset()
	return t
}

// reset prepares a fresh generation. readerWG.Wait() drains stale readers from
// the previous attempt so they cannot poison the new state.
func (t *Tunnel) reset() {
	t.readerWG.Wait()
	t.listeners = nil
	t.clients = make(map[uint32]*Client)
	t.acceptCh = make(chan acceptConn, 16)
	t.done = make(chan struct{})
	t.cseqCounter = CSEQ_BASE
	t.socksMu.Lock()
	t.deviceRemote = nil
	t.mainRemote = nil
	t.tou = nil
	t.useTCPPath = false
	t.socksMu.Unlock()
	t.primary = nil
	t.chanKey = nil
	t.bindWait = make(map[uint32]chan struct{})
	t.pools = make(map[int]*poolState)
	t.failErr = nil
}

func (t *Tunnel) close() {
	select {
	case <-t.done:
	default:
		close(t.done)
	}
	for _, ln := range t.listeners {
		ln.Close()
	}
	t.clientsMu.Lock()
	for _, c := range t.clients {
		c.conn.Close()
	}
	t.clientsMu.Unlock()
	t.socksMu.Lock()
	dr, mr, tou := t.deviceRemote, t.mainRemote, t.tou
	t.socksMu.Unlock()
	if dr != nil {
		dr.Close()
	}
	if mr != nil {
		mr.Close()
	}
	if tou != nil {
		tou.close()
	}
}

func (t *Tunnel) Run() error {
	if err := t.handshake(); err != nil {
		t.close()
		return err
	}
	defer t.close()
	return t.serve()
}

func (t *Tunnel) logf(format string, args ...any) {
	if !t.debug {
		return
	}
	msg := fmt.Sprintf(format, args...)
	if t.ui != nil {
		t.ui.Below(msg)
	} else {
		fmt.Println(msg)
	}
}

// statusf advances the progress bar to the given phase.
// In debug mode the status is also emitted as a log line.
func (t *Tunnel) statusf(phase int, status string) {
	if t.progress != nil {
		t.progress.Phase(phase, status)
	}
	t.logf("[phase %d] %s", phase, status)
}

func (t *Tunnel) markConnecting() {
	if t.reg == nil {
		return
	}
	for _, idx := range t.specIdx {
		t.reg.connecting(idx)
	}
}

// channelRequest is one logical /device/<SN>/p2p-channel exchange. The
// identity fields — CSeq, x-pcs-request-id, Identify, CreateDate, ClientId,
// RandSalt — are fixed at construction; every (re)send refreshes the crypto
// fields — Nonce, DevAuth, encrypted LocalAddr (and the WSSE digest, which
// buildDHRequest regenerates per datagram) — via regenerate(). This mirrors
// the DMSS app's retransmission behavior (capture: ~550 ms re-sends;
// spike/README.md §"DMSS profile").
type channelRequest struct {
	prof *appProfile

	dtype    int
	username string
	key      []byte // Type-1 master key (nil for Type 0)
	randsalt string

	lport int // local UDP port encrypted into LocalAddr

	bindIP       string   // egress IP toward the p2p server (final LocalAddr entry)
	addrPrefixes []string // interface IPv4s (leading bare-IP LocalAddr entries)

	cseq     uint32
	pcsID    string // x-pcs-request-id (DMSS only, else "")
	identify string // 8 bytes, space-separated hex
	created  int64  // CreateDate (unix seconds; fixed per logical request)
	clientID string // "<32 hex>:<fwdPort>" (DMSS only, else "")

	nonce    int
	laddrEnc string // LocalAddr ciphertext the DevAuth signature covers
}

// newChannelRequest builds one logical channel request and derives its
// first crypto generation. bindIP is the socket's egress IP toward the p2p
// server (UDP.bindIP) — the final LocalAddr entry; the interface prefixes
// are enumerated once here so every (re)send signs the same address list.
func newChannelRequest(prof *appProfile, dtype int, username, password, randsalt string, aid []byte, bindIP string, lport, fwdPort int) *channelRequest {
	cr := &channelRequest{
		prof:         prof,
		dtype:        dtype,
		username:     username,
		randsalt:     randsalt,
		bindIP:       bindIP,
		addrPrefixes: localAddrPrefixes(bindIP),
		lport:        lport,
		// Profile dialect: global counter for smartpss, random signed
		// int32 for dmss (app parity; live-proven wire shape). Allocated
		// once — retransmissions replay this exact value.
		cseq:     nextCSeqFor(prof),
		identify: identifyHex(aid, prof),
		created:  time.Now().Unix(),
	}
	if prof.pcsRequestID {
		cr.pcsID = randomHex(16)
		cr.clientID = fmt.Sprintf("%s:%d", randomHex(16), fwdPort)
	}
	if dtype > 0 {
		cr.key = getDeriveKey(username, password, randsalt)
	}
	cr.regenerate()
	return cr
}

// identifyHex renders the 8 aid bytes as space-separated hex. The DMSS app
// zero-pads each byte to two digits; dh-fwd's legacy smartpss format is
// unpadded — kept byte-for-byte for the default profile.
func identifyHex(aid []byte, prof *appProfile) string {
	parts := make([]string, len(aid))
	for i, b := range aid {
		format := "%x"
		if prof.extendedBody {
			format = "%02x"
		}
		parts[i] = fmt.Sprintf(format, b)
	}
	return strings.Join(parts, " ")
}

// localAddrPrefixes enumerates this host's IPv4 addresses for the LocalAddr
// CSV's bare-IP prefix entries: loopback, IPv4 link-local (169.254.0.0/16)
// and the bind IP itself are skipped — the bind is always appended as the
// final host:port entry, so advertising it twice as a prefix would only
// bloat the payload. Order follows net.Interfaces().
func localAddrPrefixes(bindIP string) []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() || ip4.IsUnspecified() {
				continue
			}
			if s := ip4.String(); s != bindIP {
				out = append(out, s)
			}
		}
	}
	return out
}

// buildLocalAddr renders the LocalAddr payload the way the DMSS app emits
// it: a comma-separated list of bare-IP interface prefixes followed by the
// final "bindIP:port" entry. This is the DMSS app's wire form, kept for app
// parity: the earlier "single-entry → 403" live bracket (2026-09-06) ran
// with dh-fwd's header serialization and is confounded — later live
// evidence showed the header serialization was the discriminator, not the
// LocalAddr shape. At least one prefix is mandatory; when the host exposes
// no other IPv4, the bind IP doubles as the prefix (the duplicate is
// parse-safe).
func buildLocalAddr(prefixes []string, bindIP string, lport int) string {
	last := bindIP + ":" + strconv.Itoa(lport)
	if len(prefixes) == 0 {
		return bindIP + "," + last
	}
	return strings.Join(prefixes, ",") + "," + last
}

// localAddr renders the plaintext LocalAddr encrypted into the request:
// the app-format CSV (buildLocalAddr) of this socket's addresses.
func (cr *channelRequest) localAddr() string {
	return buildLocalAddr(cr.addrPrefixes, cr.bindIP, cr.lport)
}

// regenerate refreshes the per-send crypto fields (Nonce + the encrypted
// LocalAddr the DevAuth signature covers) while keeping the logical identity
// fixed — fresh crypto, same request.
func (cr *channelRequest) regenerate() {
	cr.nonce = getNonce()
	if cr.dtype > 0 {
		cr.laddrEnc = getEnc(cr.key, cr.nonce, cr.localAddr())
	}
}

// body renders the p2p-channel XML for the current crypto generation.
// The DevAuth signature covers the ENCRYPTED LocalAddr string (dh-p2p
// PR#29/#33, verified against captured traffic on fw 6.7.30) for both
// profiles — signing the plaintext was dh-fwd's Type-1 bug.
func (cr *channelRequest) body() string {
	encryptTag := "<IpEncrpt>true</IpEncrpt>"
	laddr := fmt.Sprintf("<LocalAddr>%s</LocalAddr>", cr.localAddr())
	authStr := ""
	if cr.dtype > 0 {
		encryptTag = "<IpEncrptV2>true</IpEncrptV2>"
		laddr = fmt.Sprintf("<LocalAddr>%s</LocalAddr>", cr.laddrEnc)
		authStr = getAuthAt(cr.username, cr.key, cr.nonce, cr.laddrEnc, cr.randsalt, cr.created)
	}

	var sb strings.Builder
	sb.WriteString("<body>")
	sb.WriteString(authStr)
	fmt.Fprintf(&sb, "<Identify>%s</Identify>", cr.identify)
	sb.WriteString(encryptTag)
	if cr.prof.extendedBody {
		// DMSS capture element order: LocalAddr sits between <sVersion>
		// and <Pid>, not next to the encryption tag.
		fmt.Fprintf(&sb,
			"<NatValueT>0</NatValueT><version>%s</version><sVersion>%s</sVersion>",
			cr.prof.version, cr.prof.sversion)
		sb.WriteString(laddr)
		fmt.Fprintf(&sb, "<Pid>0</Pid><ClientId>%s</ClientId>", cr.clientID)
	} else {
		// Legacy smartpss position: right after the encryption tag.
		sb.WriteString(laddr)
		sb.WriteString("<version>5.0.0</version>")
	}
	sb.WriteString("</body>")
	return sb.String()
}

// channelSender binds one logical channelRequest to the socket and path it
// travels on. Both the tunnel handshake and the multi-mode preflight
// (verifyDevice) go through it, so the preflight exercises the full DMSS
// channel machinery: AutoSalt already resolved, ClientId advertising a real
// forwarded port, x-pcs-request-id on the wire and app-style retransmission.
type channelSender struct {
	req  *channelRequest
	u    *UDP
	path string
}

// newChannelSender builds one logical channel request and binds it to u.
// The request allocates its CSeq once, at construction; the socket's egress
// IP (u.bindIP, resolved toward the p2p server at socket creation) becomes
// the final LocalAddr entry, and fwdPort is the representative forwarded
// camera port advertised in ClientId (DMSS).
func newChannelSender(u *UDP, serial string, prof *appProfile, dtype int, username, password, randsalt string, lport, fwdPort int, aid []byte) *channelSender {
	return &channelSender{
		req:  newChannelRequest(prof, dtype, username, password, randsalt, aid, u.bindIP, lport, fwdPort),
		u:    u,
		path: fmt.Sprintf("/device/%s/p2p-channel", serial),
	}
}

// send puts one generation of the request on the wire under the request's
// own identity — its CSeq and x-pcs-request-id — so retransmissions stay the
// same logical request; retransmit refreshes the crypto fields first.
func (cs *channelSender) send(retransmit bool) {
	if retransmit {
		cs.req.regenerate()
	}
	cs.u.RequestEx(cs.path, cs.req.body(), true, false, reqOpts{cseq: cs.req.cseq, pcsID: cs.req.pcsID})
}

// handshake establishes the tunnel and then fires the DMSS app-parity
// local-channel step. The step runs AFTER the primary path is up and on its
// own goroutine with a bounded read (localChannelAckTimeout): tunnel
// establishment is never delayed by it (it used to sit mid-handshake with a
// full RELAY_READ_TIMEOUT read). The step's inputs are snapshotted BEFORE
// the goroutine launches — the goroutine must not read mutable tunnel state
// (chanKey is cleared by reset; a reconnect cycle racing the step would
// otherwise read a nil key or race the field).
func (t *Tunnel) handshake() error {
	if err := t.establish(); err != nil {
		return err
	}
	if t.profile.localChannel {
		go t.sendLocalChannel(t.localChannelStep())
	}
	return nil
}

// waitForPTCPToken reads PTCP frames until one carries a plausible 0x17
// token body — the sign the caller slices off at [12:]. Frames with
// shorter bodies are drained and skipped: the relay agent's late 4-byte
// SYNC ack used to slip past the old "non-empty body" guard and panic
// the [12:] slice (slice bounds [12:4] crash loop — live gate round 3,
// 2026-09-06). A sub-13-byte body can never be the token, so draining it
// is strictly safer; if the token never arrives, the read timeout
// surfaces as a regular error instead of a process-killing panic.
func (t *Tunnel) waitForPTCPToken(u *UDP, timeout time.Duration) (*PTCP, error) {
	for {
		p, err := u.ReadPTCP(timeout)
		if err != nil {
			return nil, err
		}
		if len(p.Body) >= 13 {
			return p, nil
		}
		t.logf("ptcp 0x17: discarding short body (%d bytes: %x) — waiting for token", len(p.Body), p.Body)
	}
}

// establish runs the full 4-phase connection: cloud discovery, relay agent
// allocation, Server Nat Info, inverted STUN punch and PTCP negotiation.
// On STUN success t.primary = deviceRemote (direct), otherwise mainRemote
// (relay agent).
func (t *Tunnel) establish() error {
	mainRemote := NewUDP(t.profile.mainServer, t.profile.mainPort, t.debug, t.profile)
	mainRemote.debugLog = t.logf
	t.socksMu.Lock()
	t.mainRemote = mainRemote
	t.socksMu.Unlock()
	if mainRemote.initErr != nil {
		return fmt.Errorf("main socket: %v", mainRemote.initErr)
	}

	// Phase 1: cloud discovery.
	t.statusf(PhaseCloudLookup, "cloud lookup")
	mainRemote.RequestEx(t.profile.warmupPath, "", t.profile.warmupAuth, true, reqOpts{warmup: true})
	res, _ := mainRemote.RequestEx(fmt.Sprintf("/online/p2psrv/%s", t.serial), "", true, true, reqOpts{})
	if res == nil {
		return fmt.Errorf("p2psrv lookup failed")
	}
	us := res.Body["body/US"]
	if us == "" {
		return fmt.Errorf("device %s not found on p2psrv", t.serial)
	}
	p2psrv := strings.SplitN(us, ":", 2)
	p2psrvPort, _ := strconv.Atoi(p2psrv[1])

	// Warm-up probes to the device's P2P server (US). The probes are always
	// sent (wire parity with upstream); the DMSS profile additionally
	// recovers the Type-1 RandSalt from the encrypted Info blob here, before
	// the channel request derives its auth key (upstream requires --randsalt
	// for this).
	t.statusf(PhaseDeviceProbe, "device probe")
	p2psrvRemote := NewUDP(p2psrv[0], p2psrvPort, t.debug, t.profile)
	p2psrvRemote.debugLog = t.logf
	salt, err := resolveAutoSalt(t.profile, t.dtype, t.randsalt,
		probeDeviceInfo(p2psrvRemote, t.serial), t.logf)
	p2psrvRemote.Close()
	if err != nil {
		// AutoSalt required (dmss, type 1, no --randsalt) and the blob was
		// unusable — fail the attempt rather than sign with an empty salt.
		return fmt.Errorf("autosalt: %v", err)
	}
	t.randsalt = salt

	// Phase 2: relay dispatcher lookup.
	t.statusf(PhaseRelayAlloc, "relay lookup")
	var relayHost string
	var relayPort int
	if t.profile.relayAgentOptional {
		// App parity (dmss): the app NEVER calls /online/relay nor
		// /relay/agent (zero such traffic in the session captures) — its
		// data path is the punched direct channel over the main cloud
		// (Policy p2p,udprelay). The dispatcher handed out here can also
		// stall, so the lookup reads with a SHORT bounded timeout and a
		// failure only skips the relay-agent stage below.
		mainRemote.RequestEx("/online/relay", "", true, false, reqOpts{})
		res, err := mainRemote.Read(false, relayLookupTimeout)
		if err != nil {
			t.logf("relay dispatcher lookup failed (%v) — proceeding without TCP relay agent (app-parity: DMSS never uses it)", err)
		} else if parts := strings.SplitN(res.Body["body/Address"], ":", 2); len(parts) == 2 && parts[0] != "" {
			relayHost = parts[0]
			relayPort, _ = strconv.Atoi(parts[1])
		} else {
			t.logf("relay dispatcher lookup returned no address — proceeding without TCP relay agent (app-parity: DMSS never uses it)")
		}
	} else {
		res, err = mainRemote.Request("/online/relay", "", true, true)
		if err != nil {
			return fmt.Errorf("relay lookup: %v", err)
		}
		relay := strings.SplitN(res.Body["body/Address"], ":", 2)
		relayHost = relay[0]
		relayPort, _ = strconv.Atoi(relay[1])
	}

	// Data socket for the device side, bound through the main cloud host.
	deviceRemote := NewUDP(t.profile.mainServer, t.profile.mainPort, t.debug, t.profile)
	deviceRemote.debugLog = t.logf
	t.socksMu.Lock()
	t.deviceRemote = deviceRemote
	t.socksMu.Unlock()
	if deviceRemote.initErr != nil {
		return fmt.Errorf("device socket: %v", deviceRemote.initErr)
	}

	if t.dtype > 0 && (t.username == "" || t.password == "") {
		return fmt.Errorf("username and password required for type > 0")
	}

	// Phase 3: p2p-channel request with a random 8-byte session id (AID).
	t.statusf(PhaseP2PChannel, "p2p-channel")
	aid := make([]byte, 8)
	rand.Read(aid)
	fwdPort := 0
	if len(t.specs) > 0 {
		fwdPort = t.specs[0].Remote
	}
	xchg := newChannelSender(deviceRemote, t.serial, t.profile, t.dtype, t.username, t.password,
		t.randsalt, deviceRemote.lport, fwdPort, aid)
	xchg.send(false)
	t.chanKey = xchg.req.key // reused by the post-establishment local-channel step

	// DMSS profile: app-style retransmission while the request is in flight
	// (same identity, fresh crypto) so a lost first datagram doesn't cost the
	// full 15 s read timeout. smartpss keeps the single-send flow.
	var early *DHResponse
	if t.profile.channelRetransmit {
		early = waitChannelEarlyAck(deviceRemote, xchg, t.logf, channelAckWindow)
	}

	// Relay agent allocation on the main socket. Mandatory for smartpss
	// (upstream semantics byte-for-byte); BEST-EFFORT for relayAgentOptional
	// profiles (see the Phase 2 note): a short bounded read, and a dead or
	// silent dispatcher logs and continues instead of failing the attempt.
	t.statusf(PhaseRelayAlloc, "relay agent alloc")
	var agentHost string
	var agentPort int
	var agentToken string
	if relayHost != "" {
		mainRemote.SetRemote(relayHost, relayPort)
		if t.profile.relayAgentOptional {
			mainRemote.RequestEx("/relay/agent", "", true, false, reqOpts{})
			res, err = mainRemote.Read(false, relayAgentTimeout)
			if err != nil {
				t.logf("relay dispatcher unavailable — proceeding without TCP relay agent (app-parity: DMSS never uses it)")
			} else {
				agentToken = res.Body["body/Token"]
				agent := strings.SplitN(res.Body["body/Agent"], ":", 2)
				agentHost = agent[0]
				agentPort, _ = strconv.Atoi(agent[1])
			}
		} else {
			res, err = mainRemote.Request("/relay/agent", "", true, true)
			if err != nil {
				return fmt.Errorf("relay agent: %v", err)
			}
			agentToken = res.Body["body/Token"]
			agent := strings.SplitN(res.Body["body/Agent"], ":", 2)
			agentHost = agent[0]
			agentPort, _ = strconv.Atoi(agent[1])
		}
	}
	agentOK := agentHost != ""
	if agentOK {
		mainRemote.SetRemote(agentHost, agentPort)
		mainRemote.Request(fmt.Sprintf("/relay/start/%s", agentToken), "<body><Client>:0</Client></body>", true, true)
	}

	// Phase 4: Server Nat Info from the device (via cloud/US).
	t.statusf(PhaseP2PChannel, "waiting for device ack")
	if early == nil {
		t.logf("waiting for p2p-channel ack (timeout %.0fs)", RELAY_READ_TIMEOUT.Seconds())
		res, err = deviceRemote.Read(true, RELAY_READ_TIMEOUT)
		if err == nil && res.Code < 200 {
			t.logf("waiting for p2p-channel ack body (timeout %.0fs)", RELAY_READ_TIMEOUT.Seconds())
			res, err = deviceRemote.Read(true, RELAY_READ_TIMEOUT)
		}
		if err != nil {
			return fmt.Errorf("read device response: %v", err)
		}
	} else {
		res = early
	}
	if res.Code >= 400 {
		if res.Code == 404 {
			return errDeviceNotFound
		}
		if t.dtype == 0 && res.Code == 403 {
			return fmt.Errorf("device requires authentication, try --type 1 --username <user> --password <pass>")
		}
		return fmt.Errorf("device response: code=%d %s", res.Code, res.Status)
	}

	deviceLaddr := res.Body["body/LocalAddr"]
	devicePub := res.Body["body/PubAddr"]

	if t.dtype > 0 {
		nonceStr := res.Body["body/Nonce"]
		if nonceStr != "" {
			nonceVal, _ := strconv.Atoi(nonceStr)
			deviceLaddr = getDec(xchg.req.key, nonceVal, deviceLaddr)
		}
	}

	// DMSS app parity: the app also issues GET /device/<SN>/local-channel
	// (same Type-1 auth block, no LocalAddr — DevAuth covers nonce+created
	// only) once the channel is up. Fired after full establishment by
	// handshake — see there for the non-blocking discipline (M4).

	devParts := strings.SplitN(devicePub, ":", 2)
	devPort, _ := strconv.Atoi(devParts[1])
	deviceRemote.SetRemote(devParts[0], devPort)

	// Notify the device about the relay agent. Skipped when no agent was
	// allocated (dmss best-effort): the app never sends relay-channel
	// without an agent either (zero such traffic in the captures).
	// If the relay agent doesn't ack in time we retry once: cloud sometimes
	// takes a few extra seconds to propagate the relay assignment.
	if agentOK {
		t.statusf(PhaseRelayChannel, "relay-channel")
		mainRemote.SetRemote(t.profile.mainServer, t.profile.mainPort)
		authStr := ""
		if t.dtype > 0 {
			nonce2 := getNonce()
			authStr = getAuth(t.username, xchg.req.key, nonce2, "", t.randsalt)
		}
		sendRelayChannel := func() {
			mainRemote.Request(fmt.Sprintf("/device/%s/relay-channel", t.serial),
				fmt.Sprintf("<body>%s<agentAddr>%s:%d</agentAddr></body>", authStr, agentHost, agentPort),
				true, false)
		}
		sendRelayChannel()
		mainRemote.SetRemote(agentHost, agentPort)
		t.logf("waiting for relay-channel ack from agent %s:%d (timeout %.0fs)", agentHost, agentPort, RELAY_READ_TIMEOUT.Seconds())
		if _, err := mainRemote.Read(true, RELAY_READ_TIMEOUT); err != nil {
			// Retry: send relay-channel once more and wait again.
			// The cloud sometimes takes several extra seconds to propagate the
			// relay assignment to the agent; a single retry covers this case.
			t.logf("relay-channel ack timed out (%v) — retrying", err)
			t.statusf(PhaseRelayChannel, "relay-channel retry")
			mainRemote.SetRemote(t.profile.mainServer, t.profile.mainPort)
			sendRelayChannel()
			mainRemote.SetRemote(agentHost, agentPort)
			t.logf("waiting for relay-channel ack (retry, timeout %.0fs)", RELAY_READ_TIMEOUT.Seconds())
			if _, err2 := mainRemote.Read(true, RELAY_READ_TIMEOUT); err2 != nil {
				return fmt.Errorf("relay-channel read: %v", err2)
			}
		}
	}

	policy := res.Body["body/Policy"]
	tcpRelayAllowed := strings.Contains(policy, "tcprelay")

	// Forced TCP-relay mode: the TOU channel replaces PTCP-over-UDP entirely.
	if t.useTCP {
		if !agentOK {
			return fmt.Errorf("TCP relay forced but no relay agent is available")
		}
		t.statusf(PhasePTCPHandshake, "TCP relay attach")
		if err := t.attachTCPRelay(agentHost, agentPort, agentToken); err != nil {
			return err
		}
		t.logf("TCP relay channel attached (forced)")
		return nil
	}

	// PTCP over relay: SYNC then token request (0x17 -> 0x18). Only with an
	// allocated agent — without one (dmss best-effort) the punched direct
	// channel is the only data path, so establishment falls straight through
	// to the NAT punch below.
	var sign []byte
	if agentOK {
		t.statusf(PhaseNATPunch, "PTCP sync")
		mainRemote.RequestPTCP([]byte{0x00, 0x03, 0x01, 0x00})
		t.logf("waiting for ptcp sync (timeout %.0fs)", RELAY_READ_TIMEOUT.Seconds())
		p, err := mainRemote.ReadPTCP(RELAY_READ_TIMEOUT)
		if err != nil {
			// UDP relay path dead — try the TCP relay channel if the device
			// advertises tcprelay support in its policy list.
			if tcpRelayAllowed {
				t.logf("ptcp sync over UDP failed (%v) — policy allows tcprelay, trying TCP relay", err)
				t.statusf(PhasePTCPHandshake, "TCP relay fallback")
				if aerr := t.attachTCPRelay(agentHost, agentPort, agentToken); aerr == nil {
					t.logf("TCP relay channel attached (fallback)")
					return nil
				} else {
					t.logf("TCP relay fallback failed: %v", aerr)
				}
			}
			return fmt.Errorf("ptcp sync: %v", err)
		}

		t.statusf(PhaseNATPunch, "PTCP token")
		mainRemote.RequestPTCP([]byte{
			0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
		})
		t.logf("waiting for ptcp 0x17 (timeout %.0fs)", RELAY_READ_TIMEOUT.Seconds())
		p, err = t.waitForPTCPToken(mainRemote, RELAY_READ_TIMEOUT)
		if err != nil {
			return fmt.Errorf("ptcp 0x17: %v", err)
		}
		sign = p.Body[12:]
		mainRemote.RequestPTCP(nil)
	}

	// Inverted STUN punch (Level 2): build the Init packet from the AID.
	t.statusf(PhaseNATPunch, "NAT punch")
	invAid := make([]byte, 8)
	for i, b := range aid {
		invAid[i] = ^b
	}

	cookie := make([]byte, 4)
	rand.Read(cookie)
	transID := make([]byte, 12)
	rand.Read(transID)

	eaddr := make([]byte, 6)
	binary.BigEndian.PutUint16(eaddr[0:2], uint16(devPort))
	copy(eaddr[2:], net.ParseIP(devParts[0]).To4())
	for i, b := range eaddr {
		eaddr[i] = ^b
	}

	stunInit := []byte{0xFF, 0xFE, 0xFF, 0xE7}
	stunInit = append(stunInit, cookie...)
	stunInit = append(stunInit, transID...)
	stunInit = append(stunInit, []byte{0x7F, 0xD5, 0xFF, 0xF7}...)
	stunInit = append(stunInit, invAid...)
	stunInit = append(stunInit, []byte{0xFF, 0xFB, 0xFF, 0xF7, 0xFF, 0xFE}...)
	stunInit = append(stunInit, eaddr...)

	localIPStr, localPortStr, _ := strings.Cut(deviceLaddr, ":")
	localPortVal, _ := strconv.Atoi(localPortStr)

	t.logf(":%d >>> %s:%d (LocalAddr)", deviceRemote.lport, localIPStr, localPortVal)
	t.logf(":%d >>> %s:%d (PubAddr)", deviceRemote.lport, devParts[0], devPort)

	deviceRemote.SendTo(stunInit, &net.UDPAddr{IP: net.ParseIP(localIPStr), Port: localPortVal})
	deviceRemote.Send(stunInit)

	var stunResponse []byte
	deviceRemote.SetTimeout(2 * time.Second)
	deadline := time.Now().Add(10 * time.Second)
	attempt := 0

	for time.Now().Before(deadline) {
		data, addr, err := deviceRemote.RecvFrom(4096)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				attempt++
				if attempt <= 2 {
					t.logf("Retransmit STUN init (attempt %d)", attempt)
					deviceRemote.Send(stunInit)
				}
				continue
			}
			break
		}
		magic := data[:4]
		t.logf("STUN <<< %s magic=%x len=%d", addr, magic, len(data))

		if string(magic) == "\xFE\xFE\xFF\xE7" {
			stunResponse = data
			t.logf("Got STUN response (fefeffe7)")
			break
		} else if string(magic) == "\xFF\xFE\xFF\xE7" {
			t.logf("Got device cross-STUN init (fffeffe7), responding...")
			resp := make([]byte, 0, 40)
			resp = append(resp, []byte{0xFE, 0xFE, 0xFF, 0xE7}...)
			resp = append(resp, data[4:8]...)
			resp = append(resp, data[8:20]...)
			resp = append(resp, []byte{0x7F, 0xD6, 0xFF, 0xF7}...)
			resp = append(resp, invAid...)
			resp = append(resp, []byte{0xFF, 0xFB, 0xFF, 0xF7, 0xFF, 0xFE}...)
			resp = append(resp, data[34:40]...)
			deviceRemote.SendTo(resp, addr)
			t.logf("STUN >>> %s response sent", addr)
		} else {
			t.logf("Unknown magic: %x", magic)
		}
	}

	if stunResponse == nil {
		if !agentOK {
			// No relay agent to fall back on (dmss best-effort allocation):
			// without the punched channel there is no data path at all.
			return fmt.Errorf("STUN punch failed and no relay agent available — no data path")
		}
		t.logf("STUN failed — using relay agent as the data path")
		t.statusf(PhasePTCPHandshake, "relay path")
		t.primary = mainRemote
		return nil
	}

	// Confirm the direct channel with a burst of 5 Binding Confirms.
	t.statusf(PhasePTCPHandshake, "PTCP handshake")
	confirm := []byte{0xFE, 0xFE, 0xFF, 0xF3}
	confirm = append(confirm, cookie...)
	confirm = append(confirm, transID...)
	confirm = append(confirm, []byte{0x7F, 0xD6, 0xFF, 0xF7}...)
	confirm = append(confirm, invAid...)

	for range 5 {
		t.logf("Confirm >>>")
		deviceRemote.Send(confirm)
	}

	time.Sleep(300 * time.Millisecond)
	deviceRemote.SetTimeout(500 * time.Millisecond)
	for {
		data, addr, err := deviceRemote.RecvFrom(4096)
		if err != nil {
			break
		}
		t.logf("Drain <<< %s magic=%x len=%d", addr, data[:4], len(data))
	}
	deviceRemote.SetTimeout(0)

	// Direct path: full PTCP auth handshake with the sign token.
	if t.profile.noRelayAuth {
		// App relay dialect (capture 2026-09-06, spike/capture/dmss-capture2.pcap):
		// after the STUN exchange the client sends exactly ONE PTCP SYNC and
		// then BIND/DATA — never the 0x17 token request or 0x19 auth. The
		// device answers a 0x19 with body 0x00 on this generation, and the
		// 0x17/0x19 traffic on the data socket appears to invalidate the
		// channel: BINDs still get relay-fabricated 0x12 CONN acks but DATA
		// is never routed.
		t.logf("app-parity data path: SYNC only, no 0x17/0x19 auth (dmss relay dialect)")
		deviceRemote.RequestPTCP([]byte{0x00, 0x03, 0x01, 0x00})
		if _, err := deviceRemote.ReadPTCP(3 * time.Second); err != nil {
			t.logf("app-parity sync: %v (continuing on the punched channel)", err)
		}
		t.statusf(PhasePTCPHandshake, "relay path")
		t.primary = deviceRemote
		return nil
	}
	if err := ptcpHandshake(deviceRemote, sign); err != nil {
		// The STUN punch succeeded but the device rejected the direct 0x19
		// auth (observed live 2026-09-06, Picoo F1 4G: every punch completes
		// and every auth answers body 0x00 — while the relay path serves
		// video fine). Degrade to the relay agent instead of failing the
		// port — the pre-noRelayAuth fallback (dmss sessions take the
		// app-parity branch above and never reach this).
		t.logf("ptcp device handshake failed (%v) — using relay agent as the data path", err)
		t.statusf(PhasePTCPHandshake, "relay path")
		t.primary = mainRemote
		return nil
	}
	t.logf("PTCP handshake complete (direct)")
	t.primary = deviceRemote
	return nil
}

// attachTCPRelay dials the relay agent over TCP and installs the TOU
// channel as the active data path (docs/REVERSE.md §14-16).
func (t *Tunnel) attachTCPRelay(agentHost string, agentPort int, token string) error {
	ch, err := dialTCPRelay(t.profile, agentHost, agentPort, token, t.debug, t.logf)
	if err != nil {
		return err
	}
	t.socksMu.Lock()
	t.tou = ch
	t.useTCPPath = true
	t.socksMu.Unlock()
	return nil
}

// waitChannelEarlyAck implements the DMSS app's p2p-channel retransmission:
// the app re-sends the same logical request (~550 ms and ~1.1 s after the
// first datagram in the capture), keeping CSeq, x-pcs-request-id, Identify,
// CreateDate, ClientId and RandSalt while regenerating Nonce, DevAuth,
// LocalAddr and the WSSE digest. Without it, a lost first datagram costs the
// full 15 s RELAY_READ_TIMEOUT.
//
// The wait runs under ONE absolute deadline (start+ackWindow): the read
// timeout always covers only the time to the nearer of the next retransmit
// slot or the window's end, so a provisional 1xx (100 Trying) or a stream of
// unrelated datagrams can neither stretch the wait nor consume the
// retransmit budget.
//
// Matching semantics (live 2026-09-06):
//   - Any final error response (status >= 400) is TERMINAL regardless of
//     identity and returned as the outcome. The cloud's 4xx answers carry a
//     server-GENERATED x-pcs-request-id (stable per device, never an echo)
//     and would never correlate — the real error must surface instead of
//     starving the wait.
//   - 1xx/2xx answers correlate on the request's pcs-id ALONE when the
//     request carried one: the server sometimes emits `CSeq: 0` on VALID
//     responses, so CSeq-strict matching starves them. Requests without a
//     pcs-id keep CSeq matching.
//   - Nothing is consumed silently: every dropped datagram is logged with
//     its status line / first-bytes class. A late/matched ack the caller
//     misses here is still picked up by the caller's normal read path.
//
// Returns the final (>= 200) response if it arrives within the window;
// nil lets the caller fall back to the plain RELAY_READ_TIMEOUT read.
const (
	channelAckWindow  = 1800 * time.Millisecond // capture: 100 Trying ~0.7 s, 200 ~1.1 s
	channelMaxRetrans = 2
)

func waitChannelEarlyAck(u *UDP, cs *channelSender, logf func(string, ...any), ackWindow time.Duration) *DHResponse {
	step := ackWindow / 3 // default 1.8 s → re-sends at ~0.6 s / ~1.2 s (capture: ~0.55 s / ~1.1 s)
	start := time.Now()
	deadline := start.Add(ackWindow)
	nextSend := start.Add(step)
	retransmits := 0
	for {
		wait := time.Until(nextSend)
		if d := time.Until(deadline); d < wait {
			wait = d
		}
		if wait <= 0 {
			// A slot (retransmit or window end) is due right now.
			if !time.Now().Before(deadline) {
				return nil
			}
			if retransmits >= channelMaxRetrans {
				nextSend = deadline // budget spent — wait out the window
				continue
			}
			retransmits++
			logf("p2p-channel ack timeout — retransmit %d/%d (same identity, fresh crypto)", retransmits, channelMaxRetrans)
			cs.send(true)
			nextSend = nextSend.Add(step)
			continue
		}
		data, err := u.Recv(4096, wait)
		if err != nil {
			continue // slot/window handling happens at the loop head
		}
		res := ParseDHResponse(string(data))

		// Final error responses are terminal regardless of identity: the
		// cloud's 403s carry a server-generated x-pcs-request-id (never an
		// echo), so they can never correlate — surface the real error.
		if res.Code >= 400 {
			logf("p2p-channel: terminal %d %s — surfacing as the outcome", res.Code, res.Status)
			return res
		}

		// 1xx/2xx identity correlation (see the function doc for the live
		// evidence behind pcs-id-alone matching).
		drop := func(reason string) {
			logf("p2p-channel: dropping datagram (%s): %s", reason, datagramClass(data))
		}
		if want := cs.req.pcsID; want != "" {
			if got := respHeader(res, "x-pcs-request-id"); got != want {
				drop(fmt.Sprintf("x-pcs-request-id %q != %q", got, want))
				continue
			}
		} else if got := respHeader(res, "CSeq"); got != strconv.FormatUint(uint64(cs.req.cseq), 10) {
			drop(fmt.Sprintf("CSeq %q != %d", got, cs.req.cseq))
			continue
		}
		if res.Code < 200 {
			// Provisional (100 Trying): neither deadline nor budget move.
			logf("p2p-channel provisional %d %s — waiting for the final response", res.Code, res.Status)
			continue
		}
		return res
	}
}

// datagramClass renders an unmatched datagram for the drop log: the raw
// status line when it parses as DH HTTP, else a first-bytes fingerprint
// (PTCP/STUN magic, or a quoted head). Drop decisions are never silent —
// every dropped datagram names what was dropped.
func datagramClass(data []byte) string {
	if len(data) >= 4 {
		switch {
		case string(data[:4]) == "PTCP":
			return "PTCP frame"
		case data[0] == 0xfe && data[1] == 0xfe:
			return "STUN frame"
		}
	}
	head := string(data)
	if i := strings.Index(head, "\r\n"); i >= 0 {
		return "status line " + strconv.Quote(head[:i])
	}
	if len(head) > 32 {
		head = head[:32]
	}
	return "unparseable " + strconv.Quote(head)
}

// respHeader looks a response header up case-insensitively — the device's
// header casing is not guaranteed to match ours.
func respHeader(res *DHResponse, name string) string {
	for k, v := range res.Headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

// localChannelAckTimeout bounds the best-effort local-channel ack read.
// A var like RELAY_READ_TIMEOUT so tests can shrink it (M4: the step must
// never stall establishment or shutdown materially). Captured into the
// step's snapshot at launch (handshake) — the goroutine never reads the var.
var localChannelAckTimeout = 2 * time.Second

// localChannelStep is the immutable input set of one local-channel step.
// It is snapshotted before the step's goroutine launches so the step signs
// from values captured at launch time and never reads mutable tunnel state
// (or the shrinkable timeout var) afterwards.
type localChannelStep struct {
	serial, username string
	chanKey          []byte // cloned — the snapshot owns its bytes
	randsalt         string
	dtype            int
	ackTimeout       time.Duration // bounds the ack read (localChannelAckTimeout at snapshot time)
}

// localChannelStep copies the request inputs the local-channel step signs
// with. The channel key is cloned, not aliased: the snapshot stays valid
// even if the tunnel's state is reset (chanKey = nil) while the step is
// still in flight.
func (t *Tunnel) localChannelStep() localChannelStep {
	return localChannelStep{
		serial:     t.serial,
		username:   t.username,
		chanKey:    append([]byte(nil), t.chanKey...),
		randsalt:   t.randsalt,
		dtype:      t.dtype,
		ackTimeout: localChannelAckTimeout,
	}
}

// sendLocalChannel issues the DMSS app's local-channel request: same Type-1
// auth block as the channel request but with NO LocalAddr — DevAuth covers
// nonce+created only. Best-effort app-parity step: failures are logged and
// the tunnel proceeds exactly like upstream without it. Runs on a separate
// short-lived socket so it cannot steal the data path's datagrams, and its
// ack read is bounded (see handshake for the non-blocking discipline).
// Reads ONLY its snapshot and immutable tunnel fields (profile, debug) —
// never mutable state (see handshake).
func (t *Tunnel) sendLocalChannel(step localChannelStep) {
	t.logf("%s profile: sending /device/%s/local-channel (app-parity step)", t.profile.name, step.serial)
	u := NewUDP(t.profile.mainServer, t.profile.mainPort, t.debug, t.profile)
	defer u.Close()
	if u.initErr != nil {
		t.logf("%s profile: local-channel socket: %v — continuing", t.profile.name, u.initErr)
		return
	}
	body := ""
	if step.dtype > 0 {
		body = fmt.Sprintf("<body>%s</body>", getAuth(step.username, step.chanKey, getNonce(), "", step.randsalt))
	}
	u.RequestEx(fmt.Sprintf("/device/%s/local-channel", step.serial), body, true, false,
		reqOpts{verb: t.profile.verbGet})
	res, err := u.Read(false, step.ackTimeout)
	if err != nil {
		t.logf("%s profile: local-channel ack: %v — continuing", t.profile.name, err)
		return
	}
	t.logf("%s profile: local-channel: %d %s", t.profile.name, res.Code, res.Status)
}

// ptcpHandshake runs SYNC -> AUTH_REQ(0x19+sign) -> AUTH_RESP(0x1A) ->
// AUTH_FINAL(0x1B) against the peer on socket u.
func ptcpHandshake(u *UDP, signToken []byte) error {
	u.RequestPTCP([]byte{0x00, 0x03, 0x01, 0x00})
	u.logf("waiting for ptcp sync (timeout %.0fs)", RELAY_READ_TIMEOUT.Seconds())
	p, err := u.ReadPTCP(RELAY_READ_TIMEOUT)
	if err != nil {
		return err
	}
	if string(p.Body) != "\x00\x03\x01\x00" {
		return fmt.Errorf("ptcp sync mismatch")
	}

	pkt := append([]byte{0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, signToken...)
	u.RequestPTCP(pkt)
	u.logf("waiting for ptcp auth (timeout %.0fs)", RELAY_READ_TIMEOUT.Seconds())
	p, err = u.ReadPTCP(RELAY_READ_TIMEOUT)
	if err != nil {
		return err
	}
	for len(p.Body) == 0 {
		u.logf("waiting for ptcp auth body (timeout %.0fs)", RELAY_READ_TIMEOUT.Seconds())
		p, err = u.ReadPTCP(RELAY_READ_TIMEOUT)
		if err != nil {
			return err
		}
	}
	if p.Body[0] != 0x1A {
		return fmt.Errorf("ptcp auth mismatch: got 0x%02x", p.Body[0])
	}

	u.RequestPTCP([]byte{0x1B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	u.logf("waiting for ptcp final (timeout %.0fs)", RELAY_READ_TIMEOUT.Seconds())
	p, err = u.ReadPTCP(RELAY_READ_TIMEOUT)
	if err != nil {
		return err
	}
	if len(p.Body) != 0 {
		return fmt.Errorf("ptcp final expected empty")
	}
	return nil
}

// serve opens the local listeners and pumps traffic until the tunnel dies.
func (t *Tunnel) serve() error {
	type okListen struct {
		idx    int
		port   int
		remote int
	}
	oks := []okListen{}
	for i, spec := range t.specs {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", spec.Local))
		if err != nil {
			t.logf("listen :%d failed: %v", spec.Local, err)
			if t.reg != nil {
				t.reg.fail(t.specIdx[i], fmt.Sprintf("listen :%d: %v", spec.Local, err))
			}
			continue
		}
		port := spec.Local
		if port == 0 {
			if addr, ok := ln.Addr().(*net.TCPAddr); ok {
				port = addr.Port
			}
		}
		t.listeners = append(t.listeners, ln)
		oks = append(oks, okListen{idx: t.specIdx[i], port: port, remote: spec.Remote})
		go t.acceptLoop(ln, spec.Remote)
	}
	if len(t.listeners) == 0 {
		return fmt.Errorf("no listeners available for tunnel")
	}

	for _, o := range oks {
		if t.reg != nil {
			t.reg.okPort(o.idx, o.port)
		}
	}
	if t.progress != nil {
		// Single-mode: overwrite the progress bar line with the final "Listening" message.
		o := oks[0]
		t.progress.Done(fmt.Sprintf("Listening on :%d → :%d", o.port, o.remote))
	} else if t.ui == nil {
		for _, o := range oks {
			fmt.Printf("Listening on port %d, remote port %d\n", o.port, o.remote)
		}
	}

	t.primary.lastRecv = time.Now()

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
		// Realm pool keepers: maintain pre-bound realms per forwarded port
		// so browser connection waves never pay the BIND round-trip.
		t.readerWG.Add(len(oks))
		for _, o := range oks {
			t.poolMu.Lock()
			t.pools[o.remote] = &poolState{}
			t.poolMu.Unlock()
			go t.poolKeeper(done, o.remote)
		}
	}

	for {
		select {
		case <-t.done:
			t.readerWG.Wait()
			return t.failure()
		case ac := <-t.acceptCh:
			go t.handleBind(ac)
		}
	}
}

// readLoop consumes PTCP frames from one socket. done is the generation
// token captured at spawn: after a reset this goroutine must exit silently.
func (t *Tunnel) readLoop(done chan struct{}, u *UDP) {
	defer t.readerWG.Done()
	for {
		select {
		case <-done:
			return
		default:
		}

		p, err := u.ReadPTCP(5 * time.Second)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if u == t.primary && time.Since(u.LastRecv()) > HEARTBEAT_TIMEOUT {
					t.fail(fmt.Errorf("heartbeat timeout: no PTCP on primary socket for %v", HEARTBEAT_TIMEOUT))
					return
				}
				continue
			}
			select {
			case <-done:
			default:
				t.fail(err)
			}
			return
		}
		t.routePTCP(p, u)
	}
}

// touReadLoop consumes TOU frames from the TCP relay channel.
func (t *Tunnel) touReadLoop(done chan struct{}) {
	defer t.readerWG.Done()
	t.socksMu.Lock()
	ch := t.tou
	t.socksMu.Unlock()
	if ch == nil {
		return
	}
	for {
		select {
		case <-done:
			return
		default:
		}
		typ, session, payload, _, err := ch.readFrame(time.Now().Add(tcpRelayFrameTimeout))
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if time.Since(ch.LastRecv()) > HEARTBEAT_TIMEOUT {
					t.fail(fmt.Errorf("tcp relay heartbeat timeout: no TOU frames for %v", HEARTBEAT_TIMEOUT))
					return
				}
				continue
			}
			select {
			case <-done:
			default:
				t.fail(err)
			}
			return
		}
		switch typ {
		case touTypeData:
			if c := t.getClient(session); c != nil && len(payload) > 0 {
				c.writeData(payload)
			}
		case touTypeSyn:
			// Remote session open — acknowledge per TOU convention.
			ch.writeAck(session, 0)
			t.logf("tcp-relay: remote SYN session=%#010x, ACK sent", session)
		case touTypeAck, touTypeKA, touTypeSrv:
			// liveness handled via LastRecv
		default:
			t.logf("tcp-relay: frame type=0x%02x (ignored)", typ)
		}
	}
}

// touHeartbeatLoop keeps the TCP relay channel and client sessions alive.
func (t *Tunnel) touHeartbeatLoop(done chan struct{}) {
	defer t.readerWG.Done()
	hb := time.NewTicker(tcpRelayKeepaliveEvery)
	defer hb.Stop()
	for {
		select {
		case <-done:
			return
		case <-hb.C:
			t.socksMu.Lock()
			ch := t.tou
			t.socksMu.Unlock()
			if ch == nil {
				return
			}
			if err := ch.writeKeepalive(0); err != nil {
				t.fail(fmt.Errorf("tcp relay keepalive: %v", err))
				return
			}
			now := time.Now()
			t.clientsMu.Lock()
			for rid, c := range t.clients {
				if now.Sub(c.lastKeepalive) > 25*time.Second && c.remotePort == 554 {
					ka := fmt.Sprintf("OPTIONS * RTSP/1.0\r\nCSeq: %d\r\n\r\n", c.cseq)
					t.writeRealmData(rid, []byte(ka))
					c.cseq++
					c.lastKeepalive = now
				}
			}
			t.clientsMu.Unlock()
		}
	}
}

func (t *Tunnel) heartbeatLoop(done chan struct{}) {
	defer t.readerWG.Done()
	hb := time.NewTicker(5 * time.Second)
	defer hb.Stop()
	for {
		select {
		case <-done:
			return
		case <-hb.C:
			t.socksMu.Lock()
			mr := t.mainRemote
			t.socksMu.Unlock()
			if mr != nil {
				mr.RequestPTCP([]byte{})
			}
			if t.primary != nil {
				t.primary.RequestPTCP(ptcpHeartbeat)
			}

			now := time.Now()
			t.clientsMu.Lock()
			for rid, c := range t.clients {
				// Inject keepalive bytes only into RTSP realms: OPTIONS
				// would be protocol garbage inside DVRIP (37777) or HTTP
				// (80) streams. PTCP heartbeats keep the tunnel itself up.
				if now.Sub(c.lastKeepalive) > 25*time.Second && c.remotePort == 554 {
					ka := fmt.Sprintf("OPTIONS * RTSP/1.0\r\nCSeq: %d\r\n\r\n", c.cseq)
					t.writeRealmData(rid, []byte(ka))
					c.cseq++
					c.lastKeepalive = now
				}
			}
			t.clientsMu.Unlock()
		}
	}
}

func (t *Tunnel) acceptLoop(ln net.Listener, remotePort int) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		select {
		case t.acceptCh <- acceptConn{conn: conn, remotePort: remotePort}:
		case <-t.done:
			conn.Close()
			return
		}
	}
}

// popRealm takes a pre-bound realm for the remote port if available.
func (t *Tunnel) popRealm(remotePort int) (uint32, bool) {
	t.poolMu.Lock()
	defer t.poolMu.Unlock()
	st := t.pools[remotePort]
	if st == nil || len(st.queue) == 0 {
		return 0, false
	}
	r := st.queue[0]
	st.queue = st.queue[1:]
	return r, true
}

func (t *Tunnel) pushRealm(remotePort int, realm uint32) {
	t.poolMu.Lock()
	defer t.poolMu.Unlock()
	st := t.pools[remotePort]
	if st == nil || len(st.queue) >= t.poolTarget {
		return
	}
	st.queue = append(st.queue, realm)
}

// dropRealm removes a realm from the pool (device discarded it).
func (t *Tunnel) dropRealm(realm uint32) {
	t.poolMu.Lock()
	defer t.poolMu.Unlock()
	for _, st := range t.pools {
		for i, r := range st.queue {
			if r == realm {
				st.queue = append(st.queue[:i], st.queue[i+1:]...)
				return
			}
		}
	}
}

// preBindRealm opens one realm and parks it in the pool.
func (t *Tunnel) preBindRealm(remotePort int) {
	t.poolMu.Lock()
	st := t.pools[remotePort]
	if st == nil || t.poolTarget <= 0 ||
		len(st.queue)+st.inflight >= t.poolTarget {
		t.poolMu.Unlock()
		return
	}
	st.inflight++
	t.poolMu.Unlock()

	defer func() {
		t.poolMu.Lock()
		st.inflight--
		t.poolMu.Unlock()
	}()

	realmID := rand.Uint32()
	wait := make(chan struct{})
	t.setBindWait(realmID, wait)

	bindPkt := make([]byte, 20)
	bindPkt[0] = 0x11
	binary.BigEndian.PutUint32(bindPkt[4:8], realmID)
	binary.BigEndian.PutUint32(bindPkt[12:16], uint32(remotePort))
	bindPkt[16] = 0x7F
	bindPkt[19] = 0x01
	t.bindReqMu.Lock()
	t.primary.RequestPTCP(bindPkt)
	time.Sleep(3 * time.Millisecond)
	t.bindReqMu.Unlock()

	select {
	case <-wait:
		t.pushRealm(remotePort, realmID)
		t.logf("Realm pool: pre-bound realm=%#010x port=%d", realmID, remotePort)
	case <-time.After(BIND_TIMEOUT):
		t.takeBindWait(realmID)
	case <-t.done:
		t.takeBindWait(realmID)
	}
}

// poolKeeper maintains the fixed pre-bound realm level for one remote port.
func (t *Tunnel) poolKeeper(done chan struct{}, remotePort int) {
	defer t.readerWG.Done()
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-done:
			return
		case <-tick.C:
			t.poolMu.Lock()
			st := t.pools[remotePort]
			if st == nil {
				t.poolMu.Unlock()
				return
			}
			spawn := t.poolTarget - len(st.queue) - st.inflight
			if spawn < 0 {
				spawn = 0
			}
			t.poolMu.Unlock()
			for i := 0; i < spawn; i++ {
				go t.preBindRealm(remotePort)
			}
		}
	}
}

// handleBind opens one realm: random realm id, BIND frame, wait for STATUS OK.
// In TCP-relay mode the realm is a TOU session opened with a SYN frame.
// On the UDP path a pooled pre-bound realm is preferred: no BIND wait.
func (t *Tunnel) handleBind(ac acceptConn) {
	if !t.useTCPPath {
		if realmID, ok := t.popRealm(ac.remotePort); ok {
			t.logf("Realm pool: hit realm=%#010x port=%d", realmID, ac.remotePort)
			t.addClient(realmID, ac.conn, ac.remotePort)
			return
		}
	}

	realmID := rand.Uint32()
	t.logf("Binding realm=%#010x port=%d", realmID, ac.remotePort)

	if t.useTCPPath {
		t.addClient(realmID, ac.conn, ac.remotePort)
		t.socksMu.Lock()
		ch := t.tou
		t.socksMu.Unlock()
		if ch == nil {
			ac.conn.Close()
			t.delClient(realmID)
			return
		}
		if err := ch.write(touBuildSyn(realmID)); err != nil {
			t.logf("tcp-relay SYN failed realm=%#010x: %v", realmID, err)
			t.delClient(realmID)
			ac.conn.Close()
			return
		}
		t.logf("tcp-relay: SYN sent for session=%#010x (port %d)", realmID, ac.remotePort)
		return
	}

	wait := make(chan struct{})
	t.setBindWait(realmID, wait)

	bindPkt := make([]byte, 20)
	bindPkt[0] = 0x11
	binary.BigEndian.PutUint32(bindPkt[4:8], realmID)
	binary.BigEndian.PutUint32(bindPkt[12:16], uint32(ac.remotePort))
	bindPkt[16] = 0x7F
	bindPkt[19] = 0x01
	bindStart := time.Now()
	t.bindReqMu.Lock()
	t.primary.RequestPTCP(bindPkt)
	time.Sleep(10 * time.Millisecond)
	t.bindReqMu.Unlock()

	select {
	case <-wait:
		t.logf("Bind OK realm=%#010x in %v", realmID, time.Since(bindStart))
		// App parity (capture 2026-09-06): DATA flows only AFTER the realm
		// is confirmed (0x12 CONN). Wiring the client before the bind
		// pushed realm DATA ahead of the BIND — the device answers that
		// with an immediate 0x12 DISC.
		t.addClient(realmID, ac.conn, ac.remotePort)
	case <-time.After(BIND_TIMEOUT):
		t.logf("Bind FAILED realm=%#010x port=%d", realmID, ac.remotePort)
		ac.conn.Close()
		t.takeBindWait(realmID)
	case <-t.done:
		t.takeBindWait(realmID)
		ac.conn.Close()
	}
}

func (t *Tunnel) setBindWait(realmID uint32, ch chan struct{}) {
	t.bindMu.Lock()
	t.bindWait[realmID] = ch
	t.bindMu.Unlock()
}

func (t *Tunnel) takeBindWait(realmID uint32) chan struct{} {
	t.bindMu.Lock()
	defer t.bindMu.Unlock()
	ch := t.bindWait[realmID]
	delete(t.bindWait, realmID)
	return ch
}

func (t *Tunnel) addClient(realmID uint32, conn net.Conn, remotePort int) {
	t.clientsMu.Lock()
	t.clients[realmID] = &Client{
		conn:          conn,
		lastKeepalive: time.Now(),
		cseq:          t.cseqCounter,
		remotePort:    remotePort,
	}
	t.cseqCounter += CSEQ_STEP
	active := len(t.clients)
	t.clientsMu.Unlock()
	t.logf("Client realm=%#010x, %d active", realmID, active)
	go t.clientReader(conn, realmID)
}

func (t *Tunnel) getClient(realmID uint32) *Client {
	t.clientsMu.Lock()
	defer t.clientsMu.Unlock()
	return t.clients[realmID]
}

func (t *Tunnel) delClient(realmID uint32) {
	t.clientsMu.Lock()
	delete(t.clients, realmID)
	t.clientsMu.Unlock()
}

// dataSegmentMax matches the device's own segmentation observed in the
// capture (1316-byte datagrams = 1280-byte DATA payloads): sending larger
// frames triggers IP fragmentation and raises loss probability.
const dataSegmentMax = 1280

// writeRealmData pushes one realm payload down the active data path,
// segmented to wire-safe sizes.
func (t *Tunnel) writeRealmData(realm uint32, data []byte) {
	for len(data) > 0 {
		n := len(data)
		if n > dataSegmentMax {
			n = dataSegmentMax
		}
		chunk := data[:n]
		if t.useTCPPath {
			t.socksMu.Lock()
			ch := t.tou
			t.socksMu.Unlock()
			if ch == nil {
				return
			}
			ch.writeData(realm, chunk)
		} else if t.primary != nil {
			t.primary.RequestPTCP((&PTCPPayload{Realm: realm, Payload: chunk}).Bytes())
		}
		data = data[n:]
	}
}

// clientReader pumps local TCP bytes into the tunnel as realm DATA.
func (t *Tunnel) clientReader(conn net.Conn, realmID uint32) {
	buf := make([]byte, 16*1024)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if !t.useTCPPath {
				discPkt := make([]byte, 16)
				discPkt[0] = 0x12
				binary.BigEndian.PutUint32(discPkt[4:8], realmID)
				copy(discPkt[12:], "DISC")
				t.primary.RequestPTCP(discPkt)
			}
			t.logf("Disconnected realm=%#010x", realmID)
			t.delClient(realmID)
			return
		}
		t.writeRealmData(realmID, buf[:n])
	}
}

// routePTCP dispatches one inbound PTCP frame. Empty bodies are the peer's
// pure ACKs — mirror them. Data frames get a coalesced ack (ScheduleAck).
func (t *Tunnel) routePTCP(p *PTCP, src *UDP) {
	if len(p.Body) == 0 {
		src.RequestPTCP(nil)
		return
	}
	src.ScheduleAck()

	switch p.Body[0] {
	case 0x10:
		pl, err := ParsePTCPPayload(p.Body)
		if err != nil {
			return
		}
		if c := t.getClient(pl.Realm); c != nil {
			if c := t.getClient(pl.Realm); c != nil && len(pl.Payload) > 0 {
				c.writeData(pl.Payload)
			}
		}
	case 0x12:
		realm := binary.BigEndian.Uint32(p.Body[4:8])
		if ch := t.takeBindWait(realm); ch != nil {
			close(ch)
			return
		}
		t.dropRealm(realm) // device discarded a pooled realm
		if c := t.getClient(realm); c != nil {
			c.conn.Close()
			t.delClient(realm)
			t.logf("DVR DISC realm=%#010x", realm)
		}
	case 0x13:
		// Peer heartbeat — liveness is tracked via lastRecv.
	case 0x0a:
		// Flow-control / ping frame from device or relay agent; no-op.
	default:
		var sincePrimary float64
		if t.primary != nil {
			sincePrimary = time.Since(t.primary.LastRecv()).Seconds()
		}
		srcStr := "secondary"
		if src == t.primary {
			srcStr = "primary"
		}
		t.logf("PTCP type=%#04x len=%d src=%s sincePrimary=%.2fs time=%s hex=%x",
			p.Body[0], len(p.Body), srcStr, sincePrimary, time.Now().Format("15:04:05.000"), p.Body)
		if len(p.Body) >= 12 {
			tryRealm := binary.BigEndian.Uint32(p.Body[4:8])
			payload := p.Body[12:]
			if len(payload) > 0 && len(payload) <= 4096 {
				if c := t.getClient(tryRealm); c != nil {
					t.logf("Forwarding type 0x%02x as data to realm=%#010x (%d bytes)", p.Body[0], tryRealm, len(payload))
					c.writeData(payload)
				}
			}
		}
	}
}

func (t *Tunnel) fail(err error) {
	t.errMu.Lock()
	if t.failErr == nil {
		t.failErr = err
	}
	t.errMu.Unlock()
	select {
	case <-t.done:
	default:
		close(t.done)
	}
}

func (t *Tunnel) failure() error {
	t.errMu.Lock()
	defer t.errMu.Unlock()
	return t.failErr
}

func runWithRetries(t *Tunnel, cp *ConnectProgress, onExhausted func(err error)) {
	for attempt := 1; ; attempt++ {
		if cp != nil {
			cp.SetAttempt(attempt)
			t.progress = cp
		}
		attemptStart := time.Now()
		err := t.Run()
		if err == nil {
			// cp.Done() was already called from serve() when listeners came up.
			return
		}
		duration := time.Since(attemptStart)
		if errors.Is(err, errDeviceNotFound) {
			deviceNotFound(t.serial)
			if t.reg != nil {
				for _, idx := range t.specIdx {
					t.reg.fail(idx, err.Error())
				}
			}
			if cp != nil {
				cp.Fail("device not found")
			}
			if onExhausted != nil {
				onExhausted(err)
			}
			return
		}
		if attempt > RETRY_ATTEMPTS {
			if t.reg != nil {
				for _, idx := range t.specIdx {
					t.reg.fail(idx, err.Error())
				}
			}
			if cp != nil {
				cp.Fail(err.Error())
			}
			if onExhausted != nil {
				onExhausted(err)
			}
			return
		}
		t.markConnecting()
		msg := fmt.Sprintf("Tunnel failed after %.1fs, reason - %v, retrying %d/%d", duration.Seconds(), err, attempt, RETRY_ATTEMPTS)
		if cp != nil {
			// Reset the bar to 0% for the next attempt, keep the error visible briefly.
			cp.Reset(fmt.Sprintf("retry %d/%d: %s", attempt+1, RETRY_ATTEMPTS, err.Error()))
		} else if t.ui != nil {
			t.ui.Below(msg)
		} else {
			fmt.Println(msg)
		}
		if t.logRetries {
			detail := fmt.Sprintf("[%s] tunnel retry %d/%d: %v", time.Now().Format(time.RFC3339), attempt, RETRY_ATTEMPTS, err)
			if t.ui != nil {
				t.ui.Below(detail)
			} else {
				fmt.Println(detail)
			}
		}
		time.Sleep(RETRY_DELAY)
		t.reset()
	}
}

// infoFields flattens a /info/device/<SN> payload into tag→value: the device
// answers either with plain JSON or with a DH response wrapping an XML body.
func infoFields(text string) (map[string]string, error) {
	fields := map[string]string{}
	if strings.HasPrefix(text, "{") {
		decoded, err := decodeInfoJSON([]byte(text))
		if err != nil {
			return nil, fmt.Errorf("json parse: %v", err)
		}
		return decoded, nil
	}
	resp := ParseDHResponse(text)
	for k, val := range resp.Body {
		fields[strings.TrimPrefix(k, "body/")] = val
	}
	return fields, nil
}

// decodeInfoJSON decodes a device Info JSON payload tolerantly: real blobs
// mix string and numeric fields ("httpport":80), which a map[string]string
// decode rejects. Scalar fields are surfaced as strings; nested
// objects/arrays are not flat Info fields and are skipped.
func decodeInfoJSON(plain []byte) (map[string]string, error) {
	dec := json.NewDecoder(strings.NewReader(string(plain)))
	dec.UseNumber()
	typed := map[string]any{}
	if err := dec.Decode(&typed); err != nil {
		return nil, fmt.Errorf("info json: %v", err)
	}
	fields := make(map[string]string, len(typed))
	for k, v := range typed {
		switch val := v.(type) {
		case string:
			fields[k] = val
		case json.Number:
			fields[k] = val.String()
		case bool:
			fields[k] = strconv.FormatBool(val)
		}
	}
	return fields, nil
}

// probeDeviceInfo performs the device-p2psrv warm-up on the socket u
// (already pointed at the device's US): /probe/device, then /info/device,
// whose response carries the encrypted Info blob. Returns the raw payload
// (nil when the device doesn't answer). Shared by the tunnel handshake and
// the multi-mode preflight, which needs the blob for the Type-1 RandSalt.
func probeDeviceInfo(u *UDP, serial string) []byte {
	u.Request(fmt.Sprintf("/probe/device/%s", serial), "", true, true)
	u.Request(fmt.Sprintf("/info/device/%s", serial), "", true, false)
	data, err := u.Recv(65536, RELAY_READ_TIMEOUT)
	if err != nil {
		return nil
	}
	return data
}

// resolveAutoSalt recovers the Type-1 RandSalt from a raw /info/device
// payload (profile.autoSalt — DMSS: the salt ships inside the encrypted
// Info blob). Every non-empty input salt is authoritative and returns
// BEFORE any decode: an explicit --randsalt, and the preflight-resolved
// salt verifyDevice hands down to the per-port tunnels via runMulti, must
// never be overwritten by a (possibly different) Info-blob salt. The blob
// is consulted only when the profile auto-resolves, the device is Type 1
// and no salt is known yet.
//
// Fail-closed: when the salt is REQUIRED for signing (autoSalt profile +
// Type 1 + no explicit --randsalt) every probe/parse/decrypt/missing-field
// failure is returned as an error, so callers never fall through to signing
// with an empty salt — the request would be silently rejected with 403.
// Choice: when the salt is NOT required (explicit --randsalt or Type 0 —
// nothing to sign), the input salt returns before decoding and Info
// failures cannot occur on this path — the blob is informational and must
// not block tunnel establishment.
func resolveAutoSalt(prof *appProfile, dtype int, randsalt string, payload []byte, logf func(string, ...any)) (string, error) {
	required := prof.autoSalt && dtype > 0 && randsalt == ""
	if payload == nil {
		if required {
			return "", fmt.Errorf("device info probe got no answer — cannot resolve the Type-1 RandSalt")
		}
		return randsalt, nil
	}
	if !prof.autoSalt || dtype == 0 || randsalt != "" {
		return randsalt, nil
	}
	salt, err := randsaltFromInfo(payload)
	if err != nil {
		if required {
			return "", fmt.Errorf("randsalt: %v", err)
		}
		logf("%s profile: randsalt from the Info blob unavailable (%v) — continuing", prof.name, err)
		return randsalt, nil
	}
	logf("%s profile: randsalt acquired from the Info blob (len=%d)", prof.name, len(salt))
	return salt, nil
}

// randsaltFromInfo recovers the Type-1 RandSalt from a raw /info/device/<SN>
// payload (DMSS profile: the salt ships in the encrypted Info blob, so
// --randsalt is not needed).
func randsaltFromInfo(payload []byte) (string, error) {
	fields, err := infoFields(strings.TrimSpace(string(payload)))
	if err != nil {
		return "", err
	}
	info := fields["Info"]
	if info == "" {
		return "", fmt.Errorf("Info field absent")
	}
	plain, err := decryptDevInfoInfo(info)
	if err != nil {
		return "", fmt.Errorf("decrypt Info: %v", err)
	}
	// Typed decode reading ONLY randsalt: real blobs mix string and numeric
	// fields ("httpport":80), which a map[string]string decode rejects.
	var inner struct {
		RandSalt string `json:"randsalt"`
	}
	if err := json.Unmarshal(plain, &inner); err != nil {
		return "", fmt.Errorf("info json: %v", err)
	}
	if inner.RandSalt == "" {
		return "", fmt.Errorf("randsalt absent from the Info blob")
	}
	return inner.RandSalt, nil
}

// queryDeviceInfo fetches /info/device/<SN> from the device's P2P server and
// decrypts the "Info" blob with the hardcoded SDK keys (docs/REVERSE.md
// 4.2), recovering randsalt / devP2PVersion for Type 1 auth.
func queryDeviceInfo(serial string, prof *appProfile, debug bool) int {
	u := NewUDP(prof.mainServer, prof.mainPort, debug, prof)
	defer u.Close()
	if u.initErr != nil {
		fmt.Fprintf(os.Stderr, "main socket: %v\n", u.initErr)
		return 1
	}
	u.RequestEx(prof.warmupPath, "", prof.warmupAuth, true, reqOpts{warmup: true})
	res, _ := u.Request(fmt.Sprintf("/online/p2psrv/%s", serial), "", true, true)
	if res == nil || res.Code >= 400 || res.Body["body/US"] == "" {
		fmt.Printf("%s doesn't exist or turned off.\n", serial)
		return 1
	}
	us := strings.SplitN(res.Body["body/US"], ":", 2)
	usPort, _ := strconv.Atoi(us[1])

	v := NewUDP(us[0], usPort, debug, prof)
	defer v.Close()
	if v.initErr != nil {
		fmt.Fprintf(os.Stderr, "device socket: %v\n", v.initErr)
		return 1
	}
	v.Request(fmt.Sprintf("/probe/device/%s", serial), "", true, true)
	v.Request(fmt.Sprintf("/info/device/%s", serial), "", true, false)

	data, err := v.Recv(65536, RELAY_READ_TIMEOUT)
	if err != nil {
		fmt.Fprintf(os.Stderr, "info read: %v\n", err)
		return 1
	}
	if debug {
		fmt.Println(strings.TrimSpace(string(data)))
	}

	fields, err := infoFields(strings.TrimSpace(string(data)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	if v2 := fields["devp2pver"]; v2 != "" {
		fmt.Printf("devP2PVersion : %s\n", v2)
	}
	if dv := fields["DevVersion"]; dv != "" {
		fmt.Printf("DevVersion    : %s\n", dv)
	}

	info := fields["Info"]
	if info == "" {
		fmt.Println("Info field   : (absent — device provided no encrypted blob)")
		return 0
	}
	plain, err := decryptDevInfoInfo(info)
	if err != nil {
		fmt.Fprintf(os.Stderr, "decrypt Info: %v\n", err)
		return 1
	}
	if !isMostlyPrintable(plain) {
		fmt.Fprintf(os.Stderr, "decrypt Info: result is not printable, raw: %x\n", plain)
		return 1
	}
	fmt.Println("Info (plain) :")
	inner, jerr := decodeInfoJSON(plain)
	if jerr == nil {
		keys := make([]string, 0, len(inner))
		for k := range inner {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("  %-16s = %s\n", k, inner[k])
		}
		if inner["randsalt"] != "" {
			fmt.Printf("\nUse: dh-fwd %s -t 1 -u <user> -P <pass> -s %s\n", serial, inner["randsalt"])
		}
	} else {
		fmt.Println(string(plain))
	}
	return 0
}

func isMostlyPrintable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	ok := 0
	for _, c := range b {
		if (c >= 0x20 && c < 0x7F) || c == '\n' || c == '\r' || c == '\t' {
			ok++
		}
	}
	return ok*100/len(b) > 90
}
