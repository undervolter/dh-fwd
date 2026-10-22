package core

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type PortState int

const (
	PortConnecting PortState = iota
	PortOK
	PortFAIL
	PortDROPPED
)

type failEntry struct {
	idx    int
	spec   PortSpec
	reason string
}

type PortRegistry struct {
	mu          sync.Mutex
	serial      string
	ui          *UI
	specs       []PortSpec
	states      []PortState
	reasons     []string
	actualPorts []int
	pending     int
	notify      chan struct{}
}

func newPortRegistry(serial string, specs []PortSpec, ui *UI) *PortRegistry {
	r := &PortRegistry{
		serial:      serial,
		ui:          ui,
		specs:       specs,
		states:      make([]PortState, len(specs)),
		reasons:     make([]string, len(specs)),
		actualPorts: make([]int, len(specs)),
		pending:     len(specs),
		notify:      make(chan struct{}, 1),
	}
	for i := range specs {
		r.states[i] = PortConnecting
		if ui != nil {
			ui.Update(i, r.line(i, PortConnecting, ""))
		}
	}
	return r
}

func (r *PortRegistry) line(idx int, st PortState, reason string) string {
	s := r.specs[idx]
	switch st {
	case PortOK:
		local := r.actualPorts[idx]
		if local == 0 {
			local = s.Local
		}
		return fmt.Sprintf("[OK] Obtained %s:%d -> 127.0.0.1:%d", r.serial, s.Remote, local)
	case PortFAIL:
		return fmt.Sprintf("[FAIL] Failed %s:%d | Reason: %s", r.serial, s.Remote, reason)
	default:
		return fmt.Sprintf("[..] Opening %s:%d | Connecting...", r.serial, s.Remote)
	}
}

func (r *PortRegistry) set(idx int, st PortState, reason string) {
	r.mu.Lock()
	old := r.states[idx]
	if st == PortConnecting && old != PortConnecting {
		r.pending++
	}
	if st != PortConnecting && old == PortConnecting {
		r.pending--
	}
	r.states[idx] = st
	r.reasons[idx] = reason
	line := r.line(idx, st, reason)
	pending := r.pending
	r.mu.Unlock()

	if r.ui != nil {
		r.ui.Update(idx, line)
	}

	if st != PortConnecting && pending == 0 {
		select {
		case r.notify <- struct{}{}:
		default:
		}
	}
}

func (r *PortRegistry) connecting(idx int) { r.set(idx, PortConnecting, "") }

func (r *PortRegistry) okPort(idx, localPort int) {
	r.mu.Lock()
	r.actualPorts[idx] = localPort
	r.mu.Unlock()
	r.set(idx, PortOK, "")
}

func (r *PortRegistry) fail(idx int, reason string) {
	r.set(idx, PortFAIL, reason)
}

func (r *PortRegistry) pendingCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.pending
}

func (r *PortRegistry) drop(idx int) {
	r.mu.Lock()
	r.states[idx] = PortDROPPED
	r.mu.Unlock()
}

func (r *PortRegistry) okCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	cnt := 0
	for _, st := range r.states {
		if st == PortOK {
			cnt++
		}
	}
	return cnt
}

func (r *PortRegistry) summary() (remotes, locals []int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, s := range r.specs {
		if r.states[i] == PortOK {
			remotes = append(remotes, s.Remote)
			l := r.actualPorts[i]
			if l == 0 {
				l = s.Local
			}
			locals = append(locals, l)
		}
	}
	return remotes, locals
}

func (r *PortRegistry) failEntries() []failEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []failEntry
	for i := range r.specs {
		if r.states[i] == PortFAIL {
			out = append(out, failEntry{idx: i, spec: r.specs[i], reason: r.reasons[i]})
		}
	}
	return out
}

func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			break
		}
		consumed := len(args) - fs.NArg()
		if consumed > 0 && args[consumed-1] == "--" {
			positional = append(positional, fs.Args()...)
			break
		}
		positional = append(positional, fs.Arg(0))
		args = fs.Args()[1:]
	}
	return positional, nil
}

func Execute() {
	var debug, logRetries, infoMode, tcpRelayMode, raceMode bool
	var smartpssPreset, portTestMode bool
	var testMTUMode bool
	var poolSize int
	var dtype int
	var username, password, randsalt string
	var threads int
	var portSpec string
	var hbTimeout time.Duration
	var appName string

	flag.BoolVar(&debug, "debug", false, "debug protocol output")
	flag.BoolVar(&debug, "d", false, "debug protocol output")
	flag.BoolVar(&infoMode, "info", false, "query /info/device/<SN> and decrypt the Info blob (randsalt, devP2PVersion)")
	flag.BoolVar(&portTestMode, "test", false, "port test: query the Info blob and print the resolved camera ports + forward plan (no tunnel)")
	flag.BoolVar(&testMTUMode, "test-mtu", false, "Path MTU diagnostic: active PMTUD probe against Dahua cloud")
	flag.BoolVar(&tcpRelayMode, "R", false, "force the TCP-relay data path (TOU over TCP)")
	flag.BoolVar(&tcpRelayMode, "tcp-relay", false, "force the TCP-relay data path (TOU over TCP)")
	flag.BoolVar(&smartpssPreset, "2", false, "SmartPSS preset: forward camera ports 80+37777 on free local ports")
	flag.BoolVar(&smartpssPreset, "smartpss", false, "SmartPSS preset: forward camera ports 80+37777 on free local ports")
	flag.BoolVar(&smartpssPreset, "smart-pss", false, "SmartPSS preset: forward camera ports 80+37777 on free local ports")
	flag.IntVar(&GlobalMTU, "mtu", 0, "network MTU override (default: auto-detect from active interface, max 1280)")
	flag.IntVar(&poolSize, "pool", 50, "pre-bound realms per forwarded port (default 50; 0 disables pooling)")
	flag.IntVar(&poolSize, "pools", 50, "pre-bound realms per forwarded port (default 50; 0 disables pooling)")
	var creds string
	flag.StringVar(&creds, "creds", "", "credentials in format username:password (sets --type 1)")
	flag.StringVar(&creds, "c", "", "credentials in format username:password (sets --type 1)")
	flag.IntVar(&dtype, "t", 0, "device type: 0 = no auth (default), 1 = with auth")
	flag.IntVar(&dtype, "type", 0, "device type: 0 = no auth (default), 1 = with auth")
	flag.StringVar(&username, "u", "", "username (required when --type 1)")
	flag.StringVar(&username, "username", "", "username (required when --type 1)")
	flag.StringVar(&password, "P", "", "password (required when --type 1)")
	flag.StringVar(&password, "password", "", "password (required when --type 1)")
	flag.StringVar(&randsalt, "s", "", "RandSalt from the info blob")
	flag.StringVar(&randsalt, "randsalt", "", "RandSalt from the info blob")
	flag.StringVar(&portSpec, "port", "", `port mapping "local:camera" (e.g. "5080,5081:80,81"); without ':' = camera ports only, local is random ephemeral (e.g. "80-85"); "0:81" = ephemeral local`)
	flag.StringVar(&portSpec, "p", "", `port mapping "local:camera" (e.g. "5080,5081:80,81"); without ':' = camera ports only, local is random ephemeral (e.g. "80-85"); "0:81" = ephemeral local`)
	flag.IntVar(&threads, "threads", 3, "number of parallel tunnels")
	flag.IntVar(&threads, "mt", 3, "number of parallel tunnels")
	flag.BoolVar(&logRetries, "log-retries", false, "log retry details")
	flag.BoolVar(&logRetries, "lr", false, "log retry details")
	flag.DurationVar(&hbTimeout, "heartbeat-timeout", 30*time.Second, "PTCP heartbeat timeout")
	flag.DurationVar(&hbTimeout, "hb", 30*time.Second, "PTCP heartbeat timeout")
	flag.BoolVar(&ForceAppRelay, "app-relay", false, "force app relay dialect (skips 0x17/0x19 token auth, for 2024+ devices and modern relays)")
	flag.BoolVar(&ForceAppRelay, "ar", false, "force app relay dialect")
	flag.StringVar(&appName, "app", "smartpss", "application profile: smartpss (default) or dmss — picks the cloud host, app credentials and request dialect (dmss for devices bound via the DMSS app)")
	var autoYes bool
	flag.BoolVar(&autoYes, "y", false, "skip confirmation prompts")
	flag.BoolVar(&autoYes, "yes", false, "skip confirmation prompts")
	flag.BoolVar(&raceMode, "race", false, "parallel race application profiles (smartpss vs dmss) and direct STUN vs relay")
	flag.Usage = usage

	positional, err := parseArgs(flag.CommandLine, os.Args[1:])
	if err != nil {
		os.Exit(2)
	}

	if creds != "" {
		parts := strings.SplitN(creds, ":", 2)
		if len(parts) != 2 || parts[0] == "" {
			fmt.Fprintln(os.Stderr, "invalid --creds format: expected username:password")
			os.Exit(1)
		}
		username = parts[0]
		password = parts[1]
		if dtype == 0 {
			dtype = 1
		}
	}

	initTerminal()
	_ = initLogger("")
	defer closeLogger()

	HEARTBEAT_TIMEOUT = hbTimeout

	// Detect whether --app was explicitly set by the operator.
	appExplicit := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "app" {
			appExplicit = true
		}
	})

	// Build the profile list: explicit --app -> single profile, no fallback;
	// default -> try smartpss then dmss (auto-detect).
	var profiles []*appProfile
	if appExplicit {
		p, err := profileByName(appName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
		profiles = []*appProfile{p}
	} else {
		profiles = profileFallbackOrder()
	}

	if testMTUMode {
		RunMTUTest(MAIN_SERVER)
		return
	}

	if len(positional) < 1 {
		flag.Usage()
		os.Exit(1)
	}
	serial := positional[0]

	if infoMode {
		os.Exit(queryDeviceInfo(serial, profiles[0], debug))
	}

	if dtype > 0 && (username == "" || password == "") {
		fmt.Fprintln(os.Stderr, "username and password required for type > 0")
		os.Exit(1)
	}

	specs, err := parsePortSpec(portSpec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "port spec: %v\n", err)
		os.Exit(1)
	}
	if smartpssPreset {
		specs = []PortSpec{{Local: 0, Remote: 80}, {Local: 0, Remote: 37777}}
	}
	if threads < 1 {
		threads = 1
	}

	// --test: resolve the camera's real ports through the SAME code path a
	// tunnel uses (probe + applyDevicePorts), print the resolved ports and
	// the forward plan, exit. No listeners, no PTCP session.
	if portTestMode {
		os.Exit(runPortTest(serial, profiles[0], specs, debug))
	}

	multi := len(specs) > 1
	poolExplicit := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "threads" || f.Name == "mt" {
			multi = true
		}
		if f.Name == "pool" || f.Name == "pools" {
			poolExplicit = true
		}
	})

	if !checkUpdate() {
		return
	}



	if tcpRelayMode {
		fmt.Println("\033[31m[!]\033[0m Dahua may not accept TCP connections!")
	}


	if multi {
		runMulti(serial, profiles, specs, threads, dtype, username, password, randsalt, debug, logRetries, tcpRelayMode, poolSize, poolExplicit, raceMode)
	} else {
		runSingle(serial, profiles, specs[0], dtype, username, password, randsalt, debug, logRetries, tcpRelayMode, poolSize, poolExplicit, raceMode)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: dh-fwd [options] <serial>
       dh-fwd <serial> [options]

General:
  --yes, -y                       skip confirmation prompts
  --debug, -d                     debug protocol output
  --log-retries, -lr              log retry details
  --heartbeat-timeout, -hb <dur>  PTCP heartbeat timeout (default 10s)
  --info                          decrypt /info/device/<SN> Info blob
                                  (prints randsalt / devP2PVersion)
  --test                          port test: resolve the camera's real ports
                                  from the Info blob (httpport/privport/
                                  rtspport) and print the forward plan,
                                  no tunnel
  --test-mtu                      run active Path MTU Discovery probe against
                                  Dahua cloud and print diagnostics
  --app-relay, -ar                force app relay dialect (skips 0x17/0x19
                                  token auth on modern devices / relays)
  --race                          race application profiles (smartpss vs dmss)
                                  in parallel for fastest connection
  --tcp-relay, -R                 force the TCP-relay data path (TOU over TCP)
  --mtu <bytes>                   network MTU override (default: auto-detect
                                  from active interface, max 1280)
  --smartpss, --smart-pss, -2     SmartPSS preset: forward 80+37777 on free
                                  local ports (DVRIP + web/API channels)
  --pool, --pools <n>             pre-bound realms per forwarded port
                                  (default 50; 0 disables pooling;
                                  an explicit value wins over the
                                  automatic pool disable on 2024+
                                  devices / dmss profile)
  --app <smartpss|dmss>           application profile (default smartpss):
                                  cloud host + app credentials + request
                                  dialect — dmss for devices bound through
                                  the DMSS app (Dolynk cloud)

Device auth:
  --creds, -c <user:pass> credentials in format username:password (sets --type 1)
  --type, -t <0|1>        device type: 0 = no auth (default), 1 = with auth
  --username, -u <name>   username (required when --type 1)
  --password, -P <pass>   password (required when --type 1)
  --randsalt, -s <salt>   RandSalt from the info blob (auto-resolved from device if omitted)

Ports:
  --port, -p <spec>       "local:camera" pairs, e.g. "5080,5081:80,81";
                          without ':' = camera ports only, local is random
                          ephemeral (e.g. "80-85"); "0:81" = ephemeral local.
                          Default: one tunnel 554:554
  --threads, -mt <n>      number of parallel tunnels (default 3)

Examples:
  dh-fwd SN -p 5080,5081:80,81
  dh-fwd SN -c admin:password -p 5080:554
  dh-fwd SN -t 1 -u admin -P undervolter -p 5080:554
  dh-fwd SN -p 1337:80
  dh-fwd --app dmss SN -c admin:secret -p 8554:554
`)
}

func parsePortSpec(portSpec string) ([]PortSpec, error) {
	if portSpec != "" {
		locals, remotes, err := parsePortLists(portSpec)
		if err != nil {
			return nil, err
		}
		return makePortSpecs(locals, remotes)
	}
	return []PortSpec{{Local: 554, Remote: 554}}, nil
}

// runPortTest resolves the camera's real ports through the SAME code path a
// tunnel uses — device probe + applyDevicePorts on a bare Tunnel — prints
// the resolved ports and the resulting forward plan, and exits without
// opening listeners or a PTCP session. Exit code: 0 = answered (blob or
// not), 1 = the device/cloud gave nothing to parse.
func runPortTest(serial string, prof *appProfile, specs []PortSpec, debug bool) int {
	fmt.Printf("port test: %s (%s profile)\n", serial, prof.displayName())

	u := NewUDP(prof.mainServer, prof.mainPort, debug, prof)
	defer u.Close()
	if u.initErr != nil {
		fmt.Fprintf(os.Stderr, "main socket: %v\n", u.initErr)
		return 1
	}
	u.RequestEx(prof.warmupPath, "", prof.warmupAuth, true, reqOpts{warmup: true})
	res, _ := u.Request(fmt.Sprintf("/online/p2psrv/%s", serial), "", true, true)
	if res == nil || res.Code >= 400 || res.Body["body/US"] == "" {
		fmt.Fprintf(os.Stderr, "device %s not found on p2psrv\n", serial)
		return 1
	}
	us := strings.SplitN(res.Body["body/US"], ":", 2)
	if len(us) < 2 {
		fmt.Fprintf(os.Stderr, "malformed US address %q\n", res.Body["body/US"])
		return 1
	}
	usPort, _ := strconv.Atoi(us[1])

	v := NewUDP(us[0], usPort, debug, prof)
	defer v.Close()
	if v.initErr != nil {
		fmt.Fprintf(os.Stderr, "device socket: %v\n", v.initErr)
		return 1
	}
	payload := probeDeviceInfo(v, serial)
	if payload == nil {
		fmt.Fprintf(os.Stderr, "no answer to /info/device — ports unknown, defaults stay (80/37777/554)\n")
		return 1
	}

	tr := &Tunnel{}
	tr.applyDevicePorts(payload)
	httpP, privP, rtspP := tr.DevicePorts()
	if httpP == 0 && privP == 0 && rtspP == 0 {
		// Context: what the device actually answered with, so "no blob"
		// is distinguishable from "answer is garbage".
		if fields, ferr := infoFields(strings.TrimSpace(string(payload))); ferr == nil {
			if dv := fields["DevVersion"]; dv != "" {
				fmt.Printf("DevVersion    : %s\n", dv)
			}
		}
		if debug {
			fmt.Printf("raw /info/device answer: %s\n", strings.TrimSpace(string(payload)))
		}
		fmt.Println("no Info blob (or no port fields in it) — defaults stay: http=80 priv=37777 rtsp=554")
		fmt.Printf("hint: cross-check the blob itself: dh-fwd %s --info\n", serial)
		return 0
	}
	if fields, ferr := infoFields(strings.TrimSpace(string(payload))); ferr == nil {
		if dv := fields["DevVersion"]; dv != "" {
			fmt.Printf("DevVersion    : %s\n", dv)
		}
	}

	label := func(real int, def int) string {
		if real == 0 {
			return fmt.Sprintf("%-5d (default — no blob field)", def)
		}
		if real != def {
			return fmt.Sprintf("%-5d (override — blob says %d)", real, real)
		}
		return fmt.Sprintf("%-5d (default)", def)
	}
	fmt.Println("camera ports:")
	fmt.Printf("  httpport : %s\n", label(httpP, 80))
	fmt.Printf("  privport : %s\n", label(privP, 37777))
	fmt.Printf("  rtspport : %s\n", label(rtspP, 554))

	fmt.Println("forward plan (local -> camera):")
	for i, s := range specs {
		remote := s.Remote
		switch remote {
		case 80:
			if httpP != 0 {
				remote = httpP
			}
		case 37777:
			if privP != 0 {
				remote = privP
			}
		case 554:
			if rtspP != 0 {
				remote = rtspP
			}
		}
		mark := ""
		if remote != s.Remote {
			mark = fmt.Sprintf("  (rewritten: %d -> %d)", s.Remote, remote)
		}
		if s.Local == 0 {
			fmt.Printf("  [%d] (ephemeral) -> %d%s\n", i, remote, mark)
			continue
		}
		fmt.Printf("  [%d] %d -> %d%s\n", i, s.Local, remote, mark)
	}
	return 0
}

func parsePortLists(spec string) (locals, remotes []int, err error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil, fmt.Errorf("empty port spec")
	}
	parts := strings.SplitN(spec, ":", 2)
	if len(parts) == 2 {
		locals, err = parseIntList(parts[0])
		if err != nil {
			return nil, nil, fmt.Errorf("invalid local ports %q: %v", parts[0], err)
		}
		remotes, err = parseIntList(parts[1])
		if err != nil {
			return nil, nil, fmt.Errorf("invalid remote ports %q: %v", parts[1], err)
		}
		return locals, remotes, nil
	}
	remotes, err = parseIntList(spec)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid camera ports %q: %v", spec, err)
	}
	if len(remotes) == 0 {
		return nil, nil, fmt.Errorf("no ports specified")
	}
	locals = make([]int, len(remotes))
	return locals, remotes, nil
}

func parseIntList(s string) ([]int, error) {
	var out []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if loStr, hiStr, ok := strings.Cut(part, "-"); ok {
			lo, err := strconv.Atoi(strings.TrimSpace(loStr))
			if err != nil {
				return nil, err
			}
			hi, err := strconv.Atoi(strings.TrimSpace(hiStr))
			if err != nil {
				return nil, err
			}
			if lo < 1 || hi > 65535 || lo > hi {
				return nil, fmt.Errorf("invalid range %q", part)
			}
			for v := lo; v <= hi; v++ {
				out = append(out, v)
			}
			continue
		}
		v, err := strconv.Atoi(part)
		if err != nil {
			return nil, err
		}
		if v < 0 || v > 65535 {
			return nil, fmt.Errorf("port out of range: %d", v)
		}
		out = append(out, v)
	}
	return out, nil
}

func makePortSpecs(locals, remotes []int) ([]PortSpec, error) {
	if len(locals) == 0 {
		return nil, fmt.Errorf("no local ports specified")
	}
	for _, r := range remotes {
		if r == 0 {
			return nil, fmt.Errorf("remote port cannot be 0")
		}
	}
	if len(remotes) == 1 {
		r := remotes[0]
		specs := make([]PortSpec, len(locals))
		for i, l := range locals {
			specs[i] = PortSpec{Local: l, Remote: r}
		}
		return specs, nil
	}
	if len(locals) != len(remotes) {
		return nil, fmt.Errorf("port count mismatch: %d local vs %d remote", len(locals), len(remotes))
	}
	specs := make([]PortSpec, len(locals))
	for i := range locals {
		specs[i] = PortSpec{Local: locals[i], Remote: remotes[i]}
	}
	return specs, nil
}

func runSingleRace(serial string, profiles []*appProfile, spec PortSpec, dtype int, username, password, randsalt string, debug, logRetries bool, tcpRelay bool, poolSize int, poolExplicit bool) {
	target := fmt.Sprintf("%s:%d", serial, spec.Remote)
	profNames := make([]string, len(profiles))
	for i, p := range profiles {
		profNames[i] = p.displayName()
	}
	fmt.Printf("[*] Parallel Racing %d profiles: [%s]\n", len(profiles), strings.Join(profNames, ", "))

	type raceResult struct {
		prof   *appProfile
		tunnel *Tunnel
		err    error
	}

	resultCh := make(chan raceResult, len(profiles))
	tunnels := make([]*Tunnel, len(profiles))

	cp := NewConnectProgress(os.Stdout, target)

	for i, prof := range profiles {
		g := specGroup{idxs: []int{0}, specs: []PortSpec{spec}}
		t := newTunnel(serial, prof, dtype, username, password, randsalt, debug, logRetries, tcpRelay, poolSize, poolExplicit, g, nil)
		t.progress = cp
		tunnels[i] = t

		go func(p *appProfile, tun *Tunnel) {
			err := tun.handshake()
			resultCh <- raceResult{prof: p, tunnel: tun, err: err}
		}(prof, t)
	}

	var winner *Tunnel
	var winnerProf *appProfile
	var first404 bool
	failedCount := 0

	for failedCount < len(profiles) {
		res := <-resultCh
		if res.err == nil {
			winner = res.tunnel
			winnerProf = res.prof
			break
		}
		if errors.Is(res.err, errDeviceNotFound) {
			first404 = true
		}
		failedCount++
		writeLog("Profile %s race attempt failed: %v", res.prof.displayName(), res.err)
	}

	// Close all losing tunnels immediately
	for _, tun := range tunnels {
		if tun != winner {
			tun.close()
		}
	}

	if winner == nil {
		cp.Fail("failed")
		if first404 {
			deviceNotFound(serial)
		} else {
			fmt.Fprintf(os.Stderr, "All profiles failed during parallel race\n")
		}
		os.Exit(1)
	}

	writeLog("Profile %s WON the race! Serving port :%d -> :%d", winnerProf.displayName(), spec.Local, spec.Remote)
	if err := winner.serve(); err != nil {
		if errors.Is(err, errZombieRelay) {
			writeLog("zombie relay detected — recovering with app relay dialect")
			winner.reset()
			runWithRetries(winner, cp, func(err error) {
				fmt.Fprintf(os.Stderr, "Tunnel failed: %v\n", err)
				os.Exit(1)
			})
			return
		}
		fmt.Fprintf(os.Stderr, "Tunnel serve error: %v\n", err)
		os.Exit(1)
	}
}

func runSingle(serial string, profiles []*appProfile, spec PortSpec, dtype int, username, password, randsalt string, debug, logRetries bool, tcpRelay bool, poolSize int, poolExplicit bool, raceMode bool) {
	target := fmt.Sprintf("%s:%d", serial, spec.Remote)
	showHeader := len(profiles) > 1

	if raceMode && len(profiles) > 1 {
		runSingleRace(serial, profiles, spec, dtype, username, password, randsalt, debug, logRetries, tcpRelay, poolSize, poolExplicit)
		return
	}

	for pi, prof := range profiles {
		if showHeader && pi == 0 {
			fmt.Printf("[%d/%d] Trying %s profile\n", pi+1, len(profiles), prof.displayName())
		}

		g := specGroup{idxs: []int{0}, specs: []PortSpec{spec}}
		t := newTunnel(serial, prof, dtype, username, password, randsalt, debug, logRetries, tcpRelay, poolSize, poolExplicit, g, nil)
		cp := NewConnectProgress(os.Stdout, target)
		t.progress = cp

		var got404 bool
		runWithRetries(t, cp, func(err error) {
			if errors.Is(err, errDeviceNotFound) {
				got404 = true
				return
			}
			if isAuthError(err) {
				fmt.Fprintf(os.Stderr, "Tunnel failed: %v\n", err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "Tunnel failed, reason - %v, giving up after %d attempts\n", err, RETRY_ATTEMPTS)
			os.Exit(1)
		})

		if !got404 {
			return // success or non-404 terminal exit
		}

		isLast := pi == len(profiles)-1
		if isLast {
			cp.Fail("failed")
			deviceNotFound(serial)
			os.Exit(1)
		}

		// Intermediate 404: render "failed (404)" in place, pause briefly, then replace lines in-place
		cp.FailInPlace("failed (404)")
		time.Sleep(400 * time.Millisecond)
		t.close()

		nextProf := profiles[pi+1]
		if showHeader {
			fmt.Printf("\033[A\r\033[2K[%d/%d] Trying %s profile\n\r\033[2K", pi+2, len(profiles), nextProf.displayName())
		} else {
			fmt.Print("\r\033[2K")
		}
	}
}

// verifyDevice performs a lightweight existence check (and, for Type 1, a
// full auth round-trip) before spawning parallel tunnels in multi mode. It
// drives the same logical channel exchange as the tunnel handshake
// (channelSender): the AutoSalt is resolved from the device's Info blob
// first, ClientId advertises a real forwarded port, the request travels
// under its own CSeq / x-pcs-request-id with the profile's retransmission
// behavior. The resolved salt is returned so every per-port tunnel reuses
// it instead of re-deriving it.
func verifyDevice(serial string, prof *appProfile, dtype int, username, password, randsalt string, specs []PortSpec, debug bool) (bool, string) {
	logf := func(format string, args ...any) {
		writeLog(format, args...)
	}
	u := NewUDP(prof.mainServer, prof.mainPort, debug, prof)
	defer u.Close()
	u.RequestEx(prof.warmupPath, "", prof.warmupAuth, true, reqOpts{warmup: true})
	res, err := u.Request(fmt.Sprintf("/online/p2psrv/%s", serial), "", true, true)
	if err != nil {
		return false, randsalt
	}
	if res == nil || res.Code >= 400 {
		return false, randsalt
	}
	if res.Body["body/US"] == "" {
		return false, randsalt
	}

	if (prof.autoSalt || dtype > 0) && dtype > 0 && randsalt == "" {
		// Only profiles that resolve the salt from the device dial the US
		// here; the legacy preflight talks to the main server alone.
		us, portStr, err := net.SplitHostPort(res.Body["body/US"])
		if err != nil {
			logf("malformed US address %q — skipping the Info-blob salt", res.Body["body/US"])
			return false, randsalt
		}
		usPort, _ := strconv.Atoi(portStr)
		v := NewUDP(us, usPort, debug, prof)
		salt, err := resolveAutoSalt(prof, dtype, randsalt, probeDeviceInfo(v, serial), logf)
		v.Close()
		if err != nil {
			// AutoSalt is required here and the blob was unusable: the
			// channel request cannot be signed — the device is unverifiable.
			logf("%v — treating the device as unreachable", err)
			return false, randsalt
		}
		randsalt = salt
	}

	fwdPort := 0
	if len(specs) > 0 {
		fwdPort = specs[0].Remote
	}
	aid := make([]byte, 8)
	rand.Read(aid)
	ch := newChannelSender(u, serial, prof, dtype, username, password, randsalt, u.lport, fwdPort, aid)
	ch.send(false)
	if prof.channelRetransmit {
		window := channelAckWindow
		if RELAY_READ_TIMEOUT < window {
			window = RELAY_READ_TIMEOUT
		}
		if early := waitChannelEarlyAck(u, ch, logf, window); early != nil {
			if early.Code >= 400 {
				if dtype == 0 && early.Code == 403 {
					fmt.Fprintln(os.Stderr, errDeviceRequireAuth)
				} else if dtype > 0 && early.Code == 403 {
					fmt.Fprintln(os.Stderr, errAuthFailed)
				}
				return false, randsalt
			}
			return true, randsalt
		}
	}
	res, err = u.Read(true, RELAY_READ_TIMEOUT)
	if err == nil && res.Code < 200 {
		res, err = u.Read(true, RELAY_READ_TIMEOUT)
	}
	if err != nil {
		return false, randsalt
	}
	if res.Code >= 400 {
		if dtype == 0 && res.Code == 403 {
			fmt.Fprintln(os.Stderr, errDeviceRequireAuth)
		} else if dtype > 0 && res.Code == 403 {
			fmt.Fprintln(os.Stderr, errAuthFailed)
		}
		return false, randsalt
	}
	return true, randsalt
}

func distribute(specs []PortSpec, threads int) []specGroup {
	groups := make([]specGroup, threads)
	for i, s := range specs {
		g := i % threads
		groups[g].idxs = append(groups[g].idxs, i)
		groups[g].specs = append(groups[g].specs, s)
	}
	return groups
}

func runMulti(serial string, profiles []*appProfile, specs []PortSpec, threads int, dtype int, username, password, randsalt string, debug, logRetries bool, tcpRelay bool, poolSize int, poolExplicit bool, raceMode bool) {
	showHeader := len(profiles) > 1

	var prof *appProfile
	salt := randsalt
	if raceMode && len(profiles) > 1 {
		fmt.Printf("[*] Parallel Racing %d profiles verification...\n", len(profiles))
		type vResult struct {
			prof *appProfile
			salt string
			ok   bool
		}
		vch := make(chan vResult, len(profiles))
		for _, p := range profiles {
			go func(pr *appProfile) {
				ok, s := verifyDevice(serial, pr, dtype, username, password, randsalt, specs, debug)
				vch <- vResult{prof: pr, salt: s, ok: ok}
			}(p)
		}
		for i := 0; i < len(profiles); i++ {
			res := <-vch
			if res.ok && prof == nil {
				prof = res.prof
				salt = res.salt
			}
		}
	} else {
		for pi, p := range profiles {
			if showHeader {
				if pi > 0 {
					fmt.Print("\033[A\r\033[2K")
				}
				fmt.Printf("[%d/%d] Trying %s profile\n", pi+1, len(profiles), p.displayName())
			}
		ok, s := verifyDevice(serial, p, dtype, username, password, randsalt, specs, debug)
		if ok {
			prof = p
			salt = s
			break
		}
		}
	}
	if prof == nil {
		deviceNotFound(serial)
		os.Exit(1)
	}
	// The preflight may have resolved the salt from the device's Info blob
	// (DMSS profile) — all tunnels below reuse it, no per-port re-derivation.
	randsalt = salt

	var remoteStrs []string
	seen := make(map[int]bool)
	for _, s := range specs {
		if !seen[s.Remote] {
			seen[s.Remote] = true
			remoteStrs = append(remoteStrs, strconv.Itoa(s.Remote))
		}
	}
	target := fmt.Sprintf("%s:%s", serial, strings.Join(remoteStrs, ","))
	cp := NewConnectProgress(os.Stdout, target)
	reg := newPortRegistry(serial, specs, nil)

	var live sync.Map
	for _, g := range distribute(specs, threads) {
		if len(g.idxs) == 0 {
			continue
		}
		t := newTunnel(serial, prof, dtype, username, password, randsalt, debug, logRetries, tcpRelay, poolSize, poolExplicit, g, reg)
		t.progress = cp
		for _, idx := range g.idxs {
			live.Store(idx, t)
		}
		go runWithRetries(t, nil, nil)
	}

	summarized := false
	for {
		<-reg.notify
		if reg.pendingCount() > 0 {
			continue
		}
		fails := reg.failEntries()
		if len(fails) > 0 {
			allNotFound := true
			for _, f := range fails {
				if !isNotFound(f.reason) {
					allNotFound = false
					break
				}
			}
			if allNotFound {
				deviceNotFound(serial)
				live.Range(func(k, v any) bool {
					v.(*Tunnel).close()
					return true
				})
				os.Exit(1)
			}
			// If at least one port connected successfully, auto-drop failed ports
			if reg.okCount() > 0 {
				for _, f := range fails {
					if v, ok := live.Load(f.idx); ok {
						v.(*Tunnel).close()
						live.Delete(f.idx)
					}
					reg.drop(f.idx)
					fmt.Printf("\r[-] Dropping %s:%d (%s)                                \n", serial, f.spec.Remote, f.reason)
				}
				continue
			}
			switch showFailPrompt(serial, fails, nil) {
			case 'c':
				live.Range(func(k, v any) bool {
					v.(*Tunnel).close()
					return true
				})
				os.Exit(0)
			case 'r':
				for _, f := range fails {
					reg.connecting(f.idx)
					g := specGroup{idxs: []int{f.idx}, specs: []PortSpec{f.spec}}
					t := newTunnel(serial, prof, dtype, username, password, randsalt, debug, logRetries, tcpRelay, poolSize, poolExplicit, g, reg)
					t.progress = cp
					live.Store(f.idx, t)
					go runWithRetries(t, nil, nil)
				}
				summarized = false
			case 'd':
				for _, f := range fails {
					if v, ok := live.Load(f.idx); ok {
						v.(*Tunnel).close()
						live.Delete(f.idx)
					}
					reg.drop(f.idx)
					fmt.Printf("\r[-] Dropping %s:%d (%s)                                \n", serial, f.spec.Remote, f.reason)
				}
				if reg.okCount() == 0 {
					fmt.Println("[-] No active ports remaining.")
					os.Exit(1)
				}
			}
			continue
		}
		if !summarized {
			_, locals := reg.summary()
			var localStrs []string
			for i, p := range locals {
				if i == 0 {
					localStrs = append(localStrs, fmt.Sprintf(":%d", p))
				} else {
					localStrs = append(localStrs, strconv.Itoa(p))
				}
			}
			if len(localStrs) == 0 {
				fmt.Println("[-] No active ports remaining.")
				os.Exit(1)
			}
			cp.Done(fmt.Sprintf("Listening on %s", strings.Join(localStrs, ", ")))
			anyRelay := false
			live.Range(func(key, value any) bool {
				if tun, ok := value.(*Tunnel); ok && !tun.IsDirect() {
					anyRelay = true
				}
				return true
			})
			if anyRelay {
				fmt.Println("\033[33m[!]\033[0m STUN punch failed! Using relay path (can be unstable)")
			} else {
				fmt.Println("\033[32m[+]\033[0m Connected via direct path!")
			}
			multiDone := make(chan struct{})
			StartUptimeTracker(multiDone)
			summarized = true
		}
	}
}

func showFailPrompt(serial string, fails []failEntry, ui *UI) byte {
	sep := strings.Repeat("!", 81)
	reasons := make([]string, len(fails))
	for i, f := range fails {
		reasons[i] = fmt.Sprintf("%d: %s", f.spec.Remote, f.reason)
	}
	println := func(s string) {
		if ui != nil {
			ui.Below(s)
		} else {
			fmt.Println(s)
		}
	}
	println(sep)
	println(fmt.Sprintf("Failed to obtain port(s) on %s. Reasons: %s", serial, strings.Join(reasons, "; ")))
	println(sep)

	reader := bufio.NewReader(os.Stdin)
	for {
		println(fmt.Sprintf("Retry failed ports, (d)rop failed, or (c)lose ALL connections to %s? (r/d/c)", serial))
		line, err := reader.ReadString('\n')
		if err != nil {
			return 'c'
		}
		trimmed := strings.ToLower(strings.TrimSpace(line))
		switch trimmed {
		case "r", "к", "р":
			return 'r'
		case "d", "д", "в", "drop", "i", "ш", "ignore":
			return 'd'
		case "c", "с", "close":
			return 'c'
		}
	}
}
