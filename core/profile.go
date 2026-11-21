package core

import (
	"crypto/rand"
	"fmt"
)

// Application profiles: every stock Dahua client (SmartPSS, DMSS) speaks the
// same P2P cloud protocol but with its own dialect — a dedicated main server,
// an embedded WSSE credential pair, a verb set and version headers of its own.
// Device resolution is pair-gated (a DMSS-bound device answers only the DMSS
// identity; replay-verified 2026-09-06 — docs/dmss/p2p-cloud-re.md §8), so
// talking to a device bound through the DMSS app requires the dmss profile.
//
// smartpss reproduces dh-fwd's pre-profile behavior byte-for-byte and stays
// the default; dmss mirrors the DMSS Android app (APK 2.6.20, session
// capture 2026-09-06 — spike/README.md §"DMSS profile").

// App constants extracted from the DMSS Android app (public, embedded in
// every DMSS build — same class of constants as the SmartPSS pair below).
const (
	DMSS_MAIN_SERVER   = "p2p.dolynkcloud.com"
	DMSS_WSSE_USERNAME = "793k5zdi4dd5f037sooag8yo_dolynkc"
	DMSS_WSSE_USERKEY  = "ef8hatgmcuk4qamgg4fxx19x33s9q1xy"
)

// appProfile captures one stock client's cloud dialect. Zero-valued fields
// mean "feature not spoken by this client" (headers omitted, steps skipped) —
// which is exactly the legacy wire format for smartpss.
type appProfile struct {
	name        string
	mainServer  string // cloud main server (serial → device resolution)
	mainPort    int    // cloud main server port
	wsseUser    string // WSSE app credential pair embedded in the client
	wsseUserKey string
	verbGet     string // DHGET vs NFGET
	verbPost    string // DHPOST vs NFPOST
	createdNow  func() string

	toUType  string // X-ToUType value; empty = header not sent
	version  string // X-Version value; empty = header not sent
	sversion string // X-Sversion value; empty = header not sent

	// Request serialization dialect. smartpss keeps dh-fwd's legacy wire
	// bytes (CSeq-first header layout, global CSeq counter); dmss mirrors
	// the app (capture 2026-09-06): version headers → x-pcs-request-id →
	// X-ToUType → CSeq → auth, and a random SIGNED-int32 CSeq per logical
	// request. Live A/B on the dmss-bound cloud: this shape answered
	// `100 Trying` + `200 Server Nat Info!` 3/3 sessions; the legacy shape
	// (CSeq first + small counter value) drew 403 DevPwd_InvalidDigest
	// despite byte-correct body crypto — order and value diverge together.
	appHeaderOrder bool
	randomCSeq     bool

	pcsRequestID      bool // x-pcs-request-id on p2p-channel requests
	extendedBody      bool // DMSS channel-body tags (NatValueT/Pid/ClientId/sVersion)
	channelRetransmit bool // app-style retransmit: same identity, fresh crypto
	localChannel      bool // app-parity GET /device/<SN>/local-channel step
	autoSalt          bool // Type-1 RandSalt read from the device Info blob
	noRelayAuth       bool // data channel carries NO 0x17/0x19 auth (app relay dialect: STUN → SYNC → BIND/DATA)

	// relayAgentOptional: the client never allocates the TCP relay agent
	// (dmss: zero /online/relay, /relay/agent and relay-channel traffic in
	// the session captures — its data path is the punched direct channel
	// over the main cloud, Policy p2p,udprelay). The dispatcher exchanges
	// then run BEST-EFFORT with a short bounded read (relayLookupTimeout /
	// relayAgentTimeout): a dead dispatcher logs and the handshake continues
	// without the agent stage instead of blocking a full RELAY_READ_TIMEOUT
	// per read and restart-looping (live 2026-09-06: the Dolynk relay
	// dispatcher answered /relay/agent with silence, 17 s × 3).
	relayAgentOptional bool

	warmupPath string // first cloud probe before /online/p2psrv/<SN>
	warmupAuth bool   // whether the warm-up probe carries WSSE auth
}

var smartpssProfile = &appProfile{
	name:        "smartpss",
	mainServer:  MAIN_SERVER,
	mainPort:    MAIN_PORT,
	wsseUser:    WSSE_USERNAME,
	wsseUserKey: WSSE_USERKEY,
	verbGet:     "DHGET",
	verbPost:    "DHPOST",
	// Legacy format: UTC stamped with a literal Z. The clock is the
	// offset-corrected one (serverTimeOffset) — WSSE Created is what a
	// skewed local clock breaks first (401 + ServerTime round-trip).
	createdNow: func() string { return nowAdjusted().UTC().Format("2006-01-02T15:04:05Z") },
	warmupPath: "/probe/p2psrv",
	warmupAuth: true,
	channelRetransmit: true,
}

var dmssProfile = &appProfile{
	name:        "dmss",
	mainServer:  DMSS_MAIN_SERVER,
	mainPort:    MAIN_PORT,
	wsseUser:    DMSS_WSSE_USERNAME,
	wsseUserKey: DMSS_WSSE_USERKEY,
	verbGet:     "NFGET",
	verbPost:    "NFPOST",
	// The app stamps local time with a numeric offset (capture 2026-09-06:
	// Created="2026-09-06T10:18:35+03:00"). The layout must be -07:00 (always
	// numeric), NOT Z07:00: the Z-form renders a literal "Z" when the process
	// runs in UTC (the Alpine container has no TZ), which is not a numeric
	// offset. Matching the phone's exact +03:00 is NOT required — the capture
	// evidence shows numeric offsets are accepted, so the container's
	// +00:00 (or any local zone) is fine.
	createdNow: func() string { return nowAdjusted().Format("2006-01-02T15:04:05-07:00") },
	toUType:    "Client/Dmss_Android",
	version:    "6.7.15",
	sversion:   "1.1.0",

	pcsRequestID:       true,
	extendedBody:       true,
	channelRetransmit:  true,
	localChannel:       true,
	autoSalt:           true,
	noRelayAuth:        true,
	relayAgentOptional: true, // app never allocates the TCP relay agent (capture parity)

	appHeaderOrder: true,
	randomCSeq:     true,

	warmupPath: "/online/stun",
	warmupAuth: false, // stun carries only X-ToUType — no auth, no version headers
}

const (
	INSTAON_MAIN_SERVER    = "instaonserver.com"
	INSTAON_CTC_SERVER     = "instaonserverctc.com"
	INSTAON_PORT           = 8800

	// KVMS Pro Lite Windows client pairs
	KVMS_WSSE_USERNAME     = "DuvCSF0EJcNIELdlJsgjXoXhh7m_kplc"
	KVMS_WSSE_USERKEY      = "CD3zmkztC63QH3NomRczYTB9lv7KXEuo"

	KVMS_CTC_WSSE_USERNAME = "dS8dT3mS0uF4mX1fO3kA0kR5xB_cpcbc"
	KVMS_CTC_WSSE_USERKEY  = "fG6uM4eV9vS2dG3jU5aH7lZ7rU9dO9bK"

	// gCMOB Android client pairs
	GCMOB_WSSE_USERNAME     = "89d61b61dc9a69fdcc03e4ff3a3be2f5"
	GCMOB_WSSE_USERKEY      = "993c7d7c95542c684c30ff9a9b831249"

	GCMOB_CTC_WSSE_USERNAME = "zH4gW1gQ6eZ1bT1sH9yP6fR2f_cbmbap"
	GCMOB_CTC_WSSE_USERKEY  = "dN2cQ9gV2qU0iR3uG0wM8oI9sK0hT9mQ"
)

var kvmsProfile = &appProfile{
	name:        "kvmsprolite",
	mainServer:  INSTAON_MAIN_SERVER,
	mainPort:    INSTAON_PORT,
	wsseUser:    KVMS_WSSE_USERNAME,
	wsseUserKey: KVMS_WSSE_USERKEY,
	verbGet:     "NFGET",
	verbPost:    "NFPOST",
	createdNow:  func() string { return nowAdjusted().Format("2006-01-02T15:04:05-07:00") },
	toUType:     "Client/KVMSProLite_Win",
	version:     "6.7.15",
	sversion:    "1.1.0",

	pcsRequestID:       true,
	extendedBody:       true,
	channelRetransmit:  true,
	localChannel:       true,
	autoSalt:           true,
	noRelayAuth:        true,
	relayAgentOptional: true,

	appHeaderOrder: true,
	randomCSeq:     true,

	warmupPath: "/online/stun",
	warmupAuth: false,
}

var kvmsCtcProfile = &appProfile{
	name:        "kvmsprolite-ctc",
	mainServer:  INSTAON_CTC_SERVER,
	mainPort:    INSTAON_PORT,
	wsseUser:    KVMS_CTC_WSSE_USERNAME,
	wsseUserKey: KVMS_CTC_WSSE_USERKEY,
	verbGet:     "NFGET",
	verbPost:    "NFPOST",
	createdNow:  func() string { return nowAdjusted().Format("2006-01-02T15:04:05-07:00") },
	toUType:     "Client/KVMSProLite_Win",
	version:     "6.7.15",
	sversion:    "1.1.0",

	pcsRequestID:       true,
	extendedBody:       true,
	channelRetransmit:  true,
	localChannel:       true,
	autoSalt:           true,
	noRelayAuth:        true,
	relayAgentOptional: true,

	appHeaderOrder: true,
	randomCSeq:     true,

	warmupPath: "/online/stun",
	warmupAuth: false,
}

var gcmobProfile = &appProfile{
	name:        "gcmob",
	mainServer:  INSTAON_MAIN_SERVER,
	mainPort:    INSTAON_PORT,
	wsseUser:    GCMOB_WSSE_USERNAME,
	wsseUserKey: GCMOB_WSSE_USERKEY,
	verbGet:     "NFGET",
	verbPost:    "NFPOST",
	createdNow:  func() string { return nowAdjusted().Format("2006-01-02T15:04:05-07:00") },
	toUType:     "Client/gCMOB_Android",
	version:     "6.7.15",
	sversion:    "1.1.0",

	pcsRequestID:       true,
	extendedBody:       true,
	channelRetransmit:  true,
	localChannel:       true,
	autoSalt:           true,
	noRelayAuth:        true,
	relayAgentOptional: true,

	appHeaderOrder: true,
	randomCSeq:     true,

	warmupPath: "/online/stun",
	warmupAuth: false,
}

var gcmobCtcProfile = &appProfile{
	name:        "gcmob-ctc",
	mainServer:  INSTAON_CTC_SERVER,
	mainPort:    INSTAON_PORT,
	wsseUser:    GCMOB_CTC_WSSE_USERNAME,
	wsseUserKey: GCMOB_CTC_WSSE_USERKEY,
	verbGet:     "NFGET",
	verbPost:    "NFPOST",
	createdNow:  func() string { return nowAdjusted().Format("2006-01-02T15:04:05-07:00") },
	toUType:     "Client/gCMOB_Android",
	version:     "6.7.15",
	sversion:    "1.1.0",

	pcsRequestID:       true,
	extendedBody:       true,
	channelRetransmit:  true,
	localChannel:       true,
	autoSalt:           true,
	noRelayAuth:        true,
	relayAgentOptional: true,

	appHeaderOrder: true,
	randomCSeq:     true,

	warmupPath: "/online/stun",
	warmupAuth: false,
}

// profileByName resolves the --app flag value.
func profileByName(name string) (*appProfile, error) {
	switch name {
	case "smartpss":
		return smartpssProfile, nil
	case "dmss":
		return dmssProfile, nil
	case "kvmsprolite", "kvms", "instaon", "instaoncloud":
		return kvmsProfile, nil
	case "kvmsprolite-ctc", "kvms-ctc", "instaon-ctc", "instaoncloud-ctc":
		return kvmsCtcProfile, nil
	case "gcmob":
		return gcmobProfile, nil
	case "gcmob-ctc":
		return gcmobCtcProfile, nil
	}
	return nil, fmt.Errorf("unknown app profile %q (want smartpss, dmss, kvmsprolite, gcmob, or -ctc variants)", name)
}

// displayName returns a human-readable label for UI output.
func (p *appProfile) displayName() string {
	switch p.name {
	case "smartpss":
		return "SmartPSS"
	case "dmss":
		return "DMSS"
	case "kvmsprolite":
		return "KVMS Pro Lite"
	case "kvmsprolite-ctc":
		return "KVMS Pro Lite (CTC)"
	case "gcmob":
		return "gCMOB"
	case "gcmob-ctc":
		return "gCMOB (CTC)"
	}
	return p.name
}

// profileFallbackOrder returns the automatic profile discovery sequence:
// smartpss first (easy4ip cloud), then dmss (Dolynk cloud), then kvmsprolite
// and gcmob (InstaOn cloud).
func profileFallbackOrder() []*appProfile {
	return []*appProfile{smartpssProfile, dmssProfile, kvmsProfile, gcmobProfile, kvmsCtcProfile, gcmobCtcProfile}
}

// randomHex returns n crypto-random bytes as 2n lowercase hex chars — the
// format of the DMSS app's x-pcs-request-id and ClientId session id.
func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
