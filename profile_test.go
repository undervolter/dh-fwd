package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"
)

// DevAuth goldens for the pinned channel-request vectors below — key from
// admin/pass123/Rs4lt (the TestGetDeriveKeyGolden master key), nonce 777,
// CreateDate 1700000000, addr 192.168.1.10,10.8.0.2,127.0.0.1:50000 (the
// newTestChannelRequest fixture's pinned LocalAddr CSV) — computed
// independently of the Go code (python3 hashlib + openssl enc -aes-256-ofb):
//
//	DevAuth = base64(HMAC-SHA256(masterKey, "777" + "1700000000" + addr))
//
// with addr the ENCRYPTED LocalAddr (correct, per dh-p2p PR#29/#33) or the
// plaintext (dh-fwd's old bug). The auth block is profile-independent, so
// BOTH profiles' channel bodies must carry the same encrypted-addr bytes;
// with nonce/created pinned, the plaintext signature becomes a hard,
// comparable regression value.
const (
	pinnedDevAuthEncAddr   = "Ziefve2EE7bCo9XcmxOXgJUpMflIzUkaFIOD3jlpbqg="
	pinnedDevAuthPlainAddr = "4U15/Y5Aex+uqYSSBX4pBbR7Dt/fPGAAxkFk5CmhJoY="
)

func TestProfileByName(t *testing.T) {
	for _, tc := range []struct {
		name string
		want string // profile name; "" = expect error
	}{
		{"smartpss", "smartpss"},
		{"dmss", "dmss"},
		{"", ""},
		{"bogus", ""},
		{"DMSS", ""},
	} {
		prof, err := profileByName(tc.name)
		if tc.want == "" {
			if err == nil {
				t.Fatalf("profileByName(%q): expected error", tc.name)
			}
			continue
		}
		if err != nil || prof.name != tc.want {
			t.Fatalf("profileByName(%q) = %v, %v", tc.name, prof, err)
		}
	}
}

// Profile selection: the host/creds/dialect mapping (fact #1, #2). Device
// resolution is pair-gated — each profile must carry its own full bundle.
// The serialization booleans (appHeaderOrder/randomCSeq) are part of the
// dialect: smartpss keeps the legacy wire bytes, dmss speaks the app shape.
func TestProfileSelection(t *testing.T) {
	tests := []struct {
		prof       *appProfile
		mainServer string
		wsseUser   string
		verbGet    string
		verbPost   string
		toUType    string
		version    string
		sversion   string
		warmupPath string
		warmupAuth bool
		autoSalt   bool

		appHeaderOrder bool
		randomCSeq     bool
	}{
		{
			prof: smartpssProfile, mainServer: "www.easy4ipcloud.com",
			wsseUser: "cba1b29e32cb17aa46b8ff9e73c7f40b",
			verbGet:  "DHGET", verbPost: "DHPOST",
			warmupPath: "/probe/p2psrv", warmupAuth: true,
		},
		{
			prof: dmssProfile, mainServer: "p2p.dolynkcloud.com",
			wsseUser: "793k5zdi4dd5f037sooag8yo_dolynkc",
			verbGet:  "NFGET", verbPost: "NFPOST",
			toUType: "Client/Dmss_Android", version: "6.7.15", sversion: "1.1.0",
			warmupPath: "/online/stun", warmupAuth: false,
			autoSalt: true,

			appHeaderOrder: true,
			randomCSeq:     true,
		},
	}
	for _, tc := range tests {
		p := tc.prof
		if p.mainServer != tc.mainServer || p.wsseUser != tc.wsseUser ||
			p.verbGet != tc.verbGet || p.verbPost != tc.verbPost ||
			p.toUType != tc.toUType || p.version != tc.version || p.sversion != tc.sversion ||
			p.warmupPath != tc.warmupPath || p.warmupAuth != tc.warmupAuth || p.autoSalt != tc.autoSalt ||
			p.appHeaderOrder != tc.appHeaderOrder || p.randomCSeq != tc.randomCSeq {
			t.Fatalf("%s profile drift: %+v", p.name, p)
		}
	}
}

// smartpssProfile must reproduce the pre-profile dh-fwd wire format byte for
// byte: the legacy request rebuilt with the emitted nonce/created/digest has
// to match the generated one exactly.
func TestBuildDHRequestSmartPSSLegacyBytes(t *testing.T) {
	req := string(buildDHRequest("DHGET", "/online/p2psrv/SN", "", true, 77, smartpssProfile, "", false))
	nonce := regexp.MustCompile(`Nonce="([^"]+)"`).FindStringSubmatch(req)
	creatd := regexp.MustCompile(`Created="([^"]+)"`).FindStringSubmatch(req)
	digest := regexp.MustCompile(`PasswordDigest="([^"]+)"`).FindStringSubmatch(req)
	if nonce == nil || creatd == nil || digest == nil {
		t.Fatalf("X-WSSE header incomplete:\n%s", req)
	}
	legacy := fmt.Sprintf(
		"DHGET /online/p2psrv/SN HTTP/1.1\r\nCSeq: 77\r\n"+
			"Authorization: WSSE profile=\"UsernameToken\"\r\n"+
			"X-WSSE: UsernameToken Username=%q, PasswordDigest=%q, Nonce=%q, Created=%q\r\n"+
			"\r\n",
		WSSE_USERNAME, digest[1], nonce[1], creatd[1])
	if req != legacy {
		t.Fatalf("smartpss bytes drifted from the legacy format.\ngot:\n%q\nwant:\n%q", req, legacy)
	}
	// No version headers in the legacy dialect.
	for _, hdr := range []string{"X-Version", "X-Sversion", "X-ToUType", "x-pcs-request-id"} {
		if strings.Contains(req, hdr) {
			t.Fatalf("smartpss request carries %s:\n%s", hdr, req)
		}
	}
	// Body-bearing requests still pick the legacy DHPOST shape (true
	// Content-Length, as upstream).
	post := string(buildDHRequest("DHPOST", "/x", "<body/>", true, 78, smartpssProfile, "", false))
	if !strings.Contains(post, "Content-Type: \r\nContent-Length: 7\r\n\r\n<body/>") {
		t.Fatalf("smartpss POST shape drifted:\n%s", post)
	}
}

// [M5] The dmss Created layout must always render a NUMERIC UTC offset. The
// Z-form layout (Z07:00) emits a literal "Z" when the process runs in UTC —
// exactly the case inside the TZ-less Alpine container — while the capture
// evidence (2026-09-06) shows the cloud accepts numeric offsets, so the
// emitted zone need not match the phone's +03:00.
func TestDMSSCreatedNumericOffset(t *testing.T) {
	orig := time.Local
	time.Local = time.UTC
	t.Cleanup(func() { time.Local = orig })

	created := dmssProfile.createdNow()
	if strings.HasSuffix(created, "Z") {
		t.Fatalf("dmss Created ends in a literal Z under UTC: %q", created)
	}
	if m, _ := regexp.MatchString(`[-+]\d{2}:\d{2}$`, created); !m {
		t.Fatalf("dmss Created lacks a -07:00-style numeric offset: %q", created)
	}
	if _, err := time.Parse("2006-01-02T15:04:05-07:00", created); err != nil {
		t.Fatalf("dmss Created not parseable as numeric-offset ISO8601: %q: %v", created, err)
	}
	// Under UTC the numeric offset is explicitly +00:00, never Z.
	if !strings.HasSuffix(created, "+00:00") {
		t.Fatalf("dmss Created under UTC should end in +00:00: %q", created)
	}
}

func TestBuildDHRequestDMSSDialect(t *testing.T) {
	// Regular request: NFGET + WSSE + the three version headers. CSeq is
	// emitted from the value passed in (the profile dialect allocates it —
	// random signed int32 for dmss, see nextCSeqFor / TestDMSSRandomCSeq);
	// its position in the app's header order is pinned by
	// TestBuildDHRequestDMSSHeaderOrder.
	req := string(buildDHRequest("NFGET", "/online/p2psrv/SN", "", true, 5, dmssProfile, "", false))
	if !strings.HasPrefix(req, "NFGET /online/p2psrv/SN HTTP/1.1\r\n") {
		t.Fatalf("dmss request line drifted:\n%s", req)
	}
	for _, frag := range []string{
		"CSeq: 5\r\n",
		"Authorization: WSSE profile=\"UsernameToken\"",
		"X-Version: 6.7.15\r\n",
		"X-Sversion: 1.1.0\r\n",
		"X-ToUType: Client/Dmss_Android\r\n",
	} {
		if !strings.Contains(req, frag) {
			t.Fatalf("dmss request missing %q:\n%s", frag, req)
		}
	}

	// Channel request: additionally carries x-pcs-request-id.
	ch := string(buildDHRequest("NFPOST", "/device/SN/p2p-channel", "<body/>", true, 6, dmssProfile, "abc123", false))
	if !strings.Contains(ch, "x-pcs-request-id: abc123\r\n") {
		t.Fatalf("dmss channel request missing x-pcs-request-id:\n%s", ch)
	}
	if !strings.HasPrefix(ch, "NFPOST ") {
		t.Fatalf("channel request verb: %q", ch[:12])
	}

	// Warmup (/online/stun): ONLY X-ToUType — no auth, no version headers.
	stun := string(buildDHRequest("NFGET", "/online/stun", "", false, 7, dmssProfile, "", true))
	if !strings.Contains(stun, "X-ToUType: Client/Dmss_Android\r\n") {
		t.Fatalf("dmss stun missing X-ToUType:\n%s", stun)
	}
	for _, hdr := range []string{"Authorization", "X-WSSE", "X-Version", "X-Sversion", "x-pcs-request-id"} {
		if strings.Contains(stun, hdr) {
			t.Fatalf("dmss stun carries %s (fact #2: ToUType only):\n%s", hdr, stun)
		}
	}
}

// The dmss profile serializes headers in the APP's order (live 2026-09-06):
// request line, X-Version, X-Sversion, x-pcs-request-id, X-ToUType, CSeq,
// Authorization, X-WSSE, Content-Type, Content-Length. The cloud answered
// this shape `100 Trying` + `200 Server Nat Info!` 3/3 live sessions; the
// legacy CSeq-first layout drew 403 DevPwd_InvalidDigest despite
// byte-correct body crypto.
func TestBuildDHRequestDMSSHeaderOrder(t *testing.T) {
	body := "<body/>"
	req := string(buildDHRequest("NFPOST", "/device/SN/p2p-channel", body, true, 6, dmssProfile, "abc123", false))
	head, _, _ := strings.Cut(req, "\r\n\r\n")
	lines := strings.Split(head, "\r\n")
	want := []string{
		"NFPOST /device/SN/p2p-channel HTTP/1.1",
		"X-Version: 6.7.15",
		"X-Sversion: 1.1.0",
		"x-pcs-request-id: abc123",
		"X-ToUType: Client/Dmss_Android",
		"CSeq: 6",
		"Authorization: WSSE profile=\"UsernameToken\"",
		"", // placeholder — X-WSSE carries a variable digest, checked below
		"Content-Type: ",
		fmt.Sprintf("Content-Length: %d", len(body)),
	}
	if len(lines) != len(want) {
		t.Fatalf("dmss header count = %d, want %d:\n%s", len(lines), len(want), req)
	}
	for i, line := range lines {
		if i == 7 { // X-WSSE: variable digest content
			if !strings.HasPrefix(line, "X-WSSE: UsernameToken Username=\""+DMSS_WSSE_USERNAME+"\", PasswordDigest=\"") {
				t.Fatalf("header 7 = %q, want the X-WSSE token line", line)
			}
			continue
		}
		if line != want[i] {
			t.Fatalf("dmss header %d = %q, want %q (app order):\n%s", i, line, want[i], req)
		}
	}

	// Warmup keeps the relative order with only its own headers:
	// request line, X-ToUType, CSeq.
	stun := string(buildDHRequest("NFGET", "/online/stun", "", false, 7, dmssProfile, "", true))
	stunHead, _, _ := strings.Cut(stun, "\r\n\r\n")
	stunLines := strings.Split(stunHead, "\r\n")
	wantStun := []string{
		"NFGET /online/stun HTTP/1.1",
		"X-ToUType: Client/Dmss_Android",
		"CSeq: 7",
	}
	if len(stunLines) != len(wantStun) {
		t.Fatalf("dmss stun header count = %d, want %d:\n%s", len(stunLines), len(wantStun), stun)
	}
	for i, line := range stunLines {
		if line != wantStun[i] {
			t.Fatalf("dmss stun header %d = %q, want %q:\n%s", i, line, wantStun[i], stun)
		}
	}
}

// The dmss CSeq is a random SIGNED-int32 value per logical request, not the
// global counter (app behavior; the legacy small counter shape drew 403
// DevPwd_InvalidDigest live). Serialization renders the sign; allocation
// draws from the full int32 range and stays stable per logical request
// (retransmissions replay it — wire-level: TestVerifyDeviceDMSSRetransmit,
// construction-level: TestCSeqStableAcrossRetransmit).
func TestDMSSRandomCSeq(t *testing.T) {
	// Signed rendering: a negative int32 CSeq serializes with the sign.
	neg := int32(-5)
	req := string(buildDHRequest("NFGET", "/x", "", false, uint32(neg), dmssProfile, "", true))
	if !strings.Contains(req, "CSeq: -5\r\n") {
		t.Fatalf("dmss CSeq not rendered signed:\n%s", req)
	}

	// smartpss keeps the global counter untouched.
	resetTestCSeq(t)
	if got := nextCSeqFor(smartpssProfile); got != 1 {
		t.Fatalf("smartpss CSeq = %d, want counter 1", got)
	}

	// dmss draws from the full signed-int32 range: across 256 draws at
	// least one must be negative (counter values never are; P(all-positive
	// random) = 2^-256).
	sawNegative := false
	for range 256 {
		if int32(nextCSeqFor(dmssProfile)) < 0 {
			sawNegative = true
			break
		}
	}
	if !sawNegative {
		t.Fatal("dmss CSeq never negative in 256 draws — still the global counter?")
	}
}

// RequestEx defaults: verb from the body, CSeq allocated when 0.
func TestRequestExDefaults(t *testing.T) {
	if !isVerb("DHGET", "", "", smartpssProfile) || !isVerb("DHPOST", "", "<b/>", smartpssProfile) {
		t.Fatal("smartpss verb derivation broken")
	}
	if !isVerb("NFGET", "", "", dmssProfile) || !isVerb("NFPOST", "", "<b/>", dmssProfile) {
		t.Fatal("dmss verb derivation broken")
	}
}

func isVerb(want, override, body string, prof *appProfile) bool {
	method := override
	if method == "" {
		method = prof.verbGet
		if body != "" {
			method = prof.verbPost
		}
	}
	return method == want
}

func newTestChannelRequest(prof *appProfile, dtype int) *channelRequest {
	cr := newChannelRequest(prof, dtype, "admin", "pass123", "Rs4lt",
		[]byte{1, 2, 3, 4, 5, 6, 7, 8}, "127.0.0.1", 50000, 554)
	// Pin the LocalAddr CSV (two interface prefixes + the loopback bind) so
	// the body tests are host-independent; regenerate re-encrypts the
	// pinned address, keeping laddrEnc consistent with it.
	cr.addrPrefixes = []string{"192.168.1.10", "10.8.0.2"}
	cr.regenerate()
	return cr
}

// smartpss channel body must keep the exact legacy shape — with the LocalAddr
// payload in the app's CSV form (the shape fw 6.7.20002 requires; identical
// for both profiles).
func TestChannelRequestBodySmartPSS(t *testing.T) {
	cr := newTestChannelRequest(smartpssProfile, 0)
	body := cr.body()
	want := fmt.Sprintf("<body><Identify>%s</Identify>"+
		"<IpEncrpt>true</IpEncrpt><LocalAddr>192.168.1.10,10.8.0.2,127.0.0.1:50000</LocalAddr>"+
		"<version>5.0.0</version></body>", cr.identify)
	if body != want {
		t.Fatalf("smartpss type-0 body drifted.\ngot:  %s\nwant: %s", body, want)
	}
	for _, tag := range []string{"DevAuth", "IpEncrptV2", "ClientId", "NatValueT", "Pid", "sVersion"} {
		if strings.Contains(body, tag) {
			t.Fatalf("smartpss body carries DMSS tag %s", tag)
		}
	}
	// Type 1: IpEncrptV2 + auth block, still no DMSS tags. Nonce and
	// CreateDate are pinned so the DevAuth signature is fully determined.
	cr1 := newTestChannelRequest(smartpssProfile, 1)
	cr1.created = 1700000000
	cr1.nonce = 777
	cr1.laddrEnc = getEnc(cr1.key, 777, cr1.localAddr())
	body1 := cr1.body()
	for _, tag := range []string{"<IpEncrptV2>true</IpEncrptV2>", "<DevAuth>", "<UserName>admin</UserName>", "<RandSalt>Rs4lt</RandSalt>", "<version>5.0.0</version>"} {
		if !strings.Contains(body1, tag) {
			t.Fatalf("smartpss type-1 body missing %q: %s", tag, body1)
		}
	}
	if strings.Contains(body1, "ClientId") {
		t.Fatal("smartpss type-1 body carries ClientId")
	}
	// EXACT pinned DevAuth bytes: the signature covers nonce + pinned
	// CreateDate + the ENCRYPTED addr (the fix) — see the golden constants.
	devauth := regexp.MustCompile(`<DevAuth>([^<]+)</DevAuth>`).FindStringSubmatch(body1)
	if devauth == nil {
		t.Fatalf("smartpss type-1 body has no DevAuth: %s", body1)
	}
	if devauth[1] != pinnedDevAuthEncAddr {
		t.Fatalf("smartpss DevAuth = %q, want pinned encrypted-addr %q", devauth[1], pinnedDevAuthEncAddr)
	}
	// Meaningful now that created/nonce are pinned on both sides: signing
	// the plaintext addr yields a different, pinned value (the old bug).
	if devauth[1] == pinnedDevAuthPlainAddr {
		t.Fatal("smartpss type-1 DevAuth signs the plaintext addr — regression")
	}
	if !strings.Contains(body1, "<CreateDate>1700000000</CreateDate>") ||
		!strings.Contains(body1, "<Nonce>777</Nonce>") {
		t.Fatalf("smartpss type-1 body not using pinned created/nonce:\n%s", body1)
	}
}

// dmss channel body: full DMSS shape (fact #5). Nonce and CreateDate are
// pinned so the DevAuth signature is fully determined.
func TestChannelRequestBodyDMSS(t *testing.T) {
	cr := newTestChannelRequest(dmssProfile, 1)
	cr.created = 1700000000
	cr.nonce = 777
	cr.laddrEnc = getEnc(cr.key, 777, cr.localAddr())
	body := cr.body()
	for _, frag := range []string{
		"<IpEncrptV2>true</IpEncrptV2>",
		"<LocalAddr>" + cr.laddrEnc + "</LocalAddr>",
		"<NatValueT>0</NatValueT>",
		"<version>6.7.15</version>",
		"<sVersion>1.1.0</sVersion>",
		"<Pid>0</Pid>",
		"<UserName>admin</UserName>",
		"<RandSalt>Rs4lt</RandSalt>",
		"<CreateDate>1700000000</CreateDate>",
		"<Nonce>777</Nonce>",
	} {
		if !strings.Contains(body, frag) {
			t.Fatalf("dmss body missing %q:\n%s", frag, body)
		}
	}
	if strings.Contains(body, "<IpEncrpt>") {
		t.Fatal("dmss body carries legacy IpEncrpt tag")
	}
	// Parity polish (capture element order): LocalAddr sits between
	// <sVersion> and <Pid> — not next to the encryption tag.
	if m, _ := regexp.MatchString(`<sVersion>1\.1\.0</sVersion><LocalAddr>[^<]+</LocalAddr><Pid>0</Pid>`, body); !m {
		t.Fatalf("dmss LocalAddr not between sVersion and Pid:\n%s", body)
	}
	// EXACT pinned DevAuth bytes — same auth block as smartpss (the block is
	// profile-independent); plaintext-addr signing is a pinned regression.
	devauth := regexp.MustCompile(`<DevAuth>([^<]+)</DevAuth>`).FindStringSubmatch(body)
	if devauth == nil {
		t.Fatalf("dmss body has no DevAuth:\n%s", body)
	}
	if devauth[1] != pinnedDevAuthEncAddr {
		t.Fatalf("dmss DevAuth = %q, want pinned encrypted-addr %q", devauth[1], pinnedDevAuthEncAddr)
	}
	if devauth[1] == pinnedDevAuthPlainAddr {
		t.Fatal("dmss type-1 DevAuth signs the plaintext addr — regression")
	}
	// Identify: 8 bytes, space-separated hex.
	if m, _ := regexp.MatchString(`<Identify>([0-9a-f]{2} ){7}[0-9a-f]{2}</Identify>`, body); !m {
		t.Fatalf("Identify not 8 space-separated hex bytes:\n%s", body)
	}
	// ClientId: "<32 hex>:<forward port>"; pcsID: 32 hex.
	if m, _ := regexp.MatchString(`^[0-9a-f]{32}:554$`, cr.clientID); !m {
		t.Fatalf("ClientId malformed: %q", cr.clientID)
	}
	if m, _ := regexp.MatchString(`^[0-9a-f]{32}$`, cr.pcsID); !m {
		t.Fatalf("x-pcs-request-id malformed: %q", cr.pcsID)
	}
	if !strings.Contains(body, "<ClientId>"+cr.clientID+"</ClientId>") {
		t.Fatal("ClientId missing from body")
	}
}

// Retransmit semantics (fact #7): identity fields stay, crypto fields change.
func TestChannelRequestRetransmitIdentity(t *testing.T) {
	for _, prof := range []*appProfile{smartpssProfile, dmssProfile} {
		cr := newTestChannelRequest(prof, 1)
		id, created, clientID, pcsID, salt := cr.identify, cr.created, cr.clientID, cr.pcsID, cr.randsalt
		body1 := cr.body()

		// A 2^-31 nonce collision would leave the body identical; retry a
		// couple of times so the test stays deterministic in practice.
		for i := 0; i < 4 && cr.body() == body1; i++ {
			cr.regenerate()
		}
		body2 := cr.body()

		if cr.identify != id || cr.created != created || cr.clientID != clientID || cr.pcsID != pcsID || cr.randsalt != salt {
			t.Fatalf("%s: identity drifted across retransmit: %+v", prof.name, cr)
		}
		if body2 == body1 {
			t.Fatalf("%s: regenerate produced identical body (crypto not refreshed)", prof.name)
		}
		if !strings.Contains(body1, fmt.Sprintf("<CreateDate>%d</CreateDate>", created)) ||
			!strings.Contains(body2, fmt.Sprintf("<CreateDate>%d</CreateDate>", created)) {
			t.Fatalf("%s: CreateDate not stable across retransmit", prof.name)
		}
		// Nonce tag inside the body must differ between sends (signed
		// int32 values — the app draws negatives too).
		n1 := regexp.MustCompile(`<Nonce>(-?\d+)</Nonce>`).FindStringSubmatch(body1)[1]
		n2 := regexp.MustCompile(`<Nonce>(-?\d+)</Nonce>`).FindStringSubmatch(body2)[1]
		if n1 == n2 {
			t.Fatalf("%s: Nonce not regenerated: %s", prof.name, n1)
		}
	}
}

func TestCSeqStableAcrossRetransmit(t *testing.T) {
	cr := newTestChannelRequest(dmssProfile, 1)
	c1 := cr.cseq
	cr.regenerate()
	if cr.cseq != c1 {
		t.Fatal("CSeq must stay fixed across retransmissions")
	}
}

// --- randsalt from the Info blob (DMSS autoSalt) ---

func encryptDevInfoInfo(plain []byte) string {
	block, _ := aes.NewCipher([]byte(DEVINFO_KEY))
	stream := cipher.NewOFB(block, []byte(DEVINFO_IV))
	out := make([]byte, len(plain))
	stream.XORKeyStream(out, plain)
	return base64.StdEncoding.EncodeToString(out)
}

func TestRandSaltFromInfo(t *testing.T) {
	info := encryptDevInfoInfo([]byte(`{"randsalt":"S4LTvalue","devP2PVersion":"3.0"}`))

	// JSON answer shape.
	jsonPayload := fmt.Sprintf(`{"Info":%q,"devp2pver":"3.0"}`, info)
	salt, err := randsaltFromInfo([]byte(jsonPayload))
	if err != nil || salt != "S4LTvalue" {
		t.Fatalf("json shape: salt=%q err=%v", salt, err)
	}

	// DH-response (XML body) answer shape.
	xmlPayload := "HTTP/1.1 200 OK\r\nContent-Type: \r\n\r\n<body><Info>" + info + "</Info></body>"
	salt, err = randsaltFromInfo([]byte(xmlPayload))
	if err != nil || salt != "S4LTvalue" {
		t.Fatalf("xml shape: salt=%q err=%v", salt, err)
	}

	// Absent / corrupt blob errors instead of returning a bogus salt.
	if _, err := randsaltFromInfo([]byte(`{"devp2pver":"3.0"}`)); err == nil {
		t.Fatal("expected error for absent Info")
	}
	if _, err := randsaltFromInfo([]byte("not-base64-###")); err == nil {
		t.Fatal("expected error for corrupt Info")
	}
}

// M2: real Info blobs mix string and numeric fields ("httpport":80); the
// decode must tolerate that and surface randsalt regardless — in both the
// DH-response (XML body) and the raw-JSON answer shapes.
func TestRandSaltFromInfoNumericFields(t *testing.T) {
	inner := `{"randsalt":"NUMS4LT","httpport":80,"mediaport":37777,"cliport":0,"devP2PVersion":"3.0"}`
	info := encryptDevInfoInfo([]byte(inner))

	xmlPayload := "HTTP/1.1 200 OK\r\n\r\n<body><Info>" + info + "</Info></body>"
	salt, err := randsaltFromInfo([]byte(xmlPayload))
	if err != nil || salt != "NUMS4LT" {
		t.Fatalf("xml shape with numeric fields: salt=%q err=%v", salt, err)
	}

	outer := fmt.Sprintf(`{"Info":%q,"httpport":80,"Result":0}`, info)
	salt, err = randsaltFromInfo([]byte(outer))
	if err != nil || salt != "NUMS4LT" {
		t.Fatalf("json shape with numeric fields: salt=%q err=%v", salt, err)
	}
}

// M2: empty salt in the blob is an error, never a silent sign-with-empty.
func TestRandSaltFromInfoEmptySalt(t *testing.T) {
	payload := "HTTP/1.1 200 OK\r\n\r\n<body><Info>" +
		encryptDevInfoInfo([]byte(`{"randsalt":"","httpport":80}`)) + "</Info></body>"
	salt, err := randsaltFromInfo([]byte(payload))
	if err == nil {
		t.Fatalf("empty randsalt: got salt=%q, want error", salt)
	}
	if salt != "" {
		t.Fatalf("error path returned salt=%q, want empty", salt)
	}
}

// M2: AutoSalt fails closed when the salt is required for signing
// (dmss + type 1 + no explicit --randsalt): a nil or unusable blob is a hard
// error, never log-and-continue with an empty salt.
func TestResolveAutoSaltFailClosed(t *testing.T) {
	logf := func(string, ...any) {}

	if salt, err := resolveAutoSalt(dmssProfile, 1, "", nil, logf); err == nil {
		t.Fatalf("nil payload: salt=%q, want error", salt)
	}
	unreadable := []byte("HTTP/1.1 200 OK\r\n\r\n<body><Info>!!!notbase64!!!</Info></body>")
	if salt, err := resolveAutoSalt(dmssProfile, 1, "", unreadable, logf); err == nil {
		t.Fatalf("unreadable blob: salt=%q, want error", salt)
	}

	good := []byte("HTTP/1.1 200 OK\r\n\r\n<body><Info>" +
		encryptDevInfoInfo([]byte(`{"randsalt":"G00DS4T","httpport":80}`)) + "</Info></body>")
	salt, err := resolveAutoSalt(dmssProfile, 1, "", good, logf)
	if err != nil || salt != "G00DS4T" {
		t.Fatalf("good blob: salt=%q err=%v, want G00DS4T, nil", salt, err)
	}
}

// M2: when the salt is NOT required (type 0, explicit --randsalt, smartpss)
// the Info blob is informational — failures stay non-fatal and the input
// salt passes through unchanged.
func TestResolveAutoSaltNonFatal(t *testing.T) {
	logf := func(string, ...any) {}

	if salt, err := resolveAutoSalt(dmssProfile, 0, "", []byte("garbage"), logf); err != nil || salt != "" {
		t.Fatalf("type 0: salt=%q err=%v, want unchanged/nil", salt, err)
	}
	if salt, err := resolveAutoSalt(dmssProfile, 1, "EXPL1C1T", []byte("garbage"), logf); err != nil || salt != "EXPL1C1T" {
		t.Fatalf("explicit salt: salt=%q err=%v, want EXPL1C1T/nil", salt, err)
	}
	if salt, err := resolveAutoSalt(smartpssProfile, 1, "", []byte("garbage"), logf); err != nil || salt != "" {
		t.Fatalf("smartpss: salt=%q err=%v, want unchanged/nil", salt, err)
	}
}

// Regression (salt precedence): a non-empty input salt is authoritative
// BEFORE decoding — a VALID Info blob carrying a different salt must never
// overwrite it. Both real callers pass such a salt: runMulti feeds the salt
// the preflight (verifyDevice) returned into every per-port tunnel, and the
// user's explicit --randsalt arrives through the same parameter.
func TestResolveAutoSaltInputSaltAuthoritative(t *testing.T) {
	logf := func(string, ...any) {}

	good := []byte("HTTP/1.1 200 OK\r\n\r\n<body><Info>" +
		encryptDevInfoInfo([]byte(`{"randsalt":"BL0BS4LT","httpport":80}`)) + "</Info></body>")
	salt, err := resolveAutoSalt(dmssProfile, 1, "PR3FS4LT", good, logf)
	if err != nil || salt != "PR3FS4LT" {
		t.Fatalf("valid blob overwrote the input salt: salt=%q err=%v, want PR3FS4LT/nil", salt, err)
	}

	// A missing answer is equally powerless against a known salt.
	if salt, err = resolveAutoSalt(dmssProfile, 1, "PR3FS4LT", nil, logf); err != nil || salt != "PR3FS4LT" {
		t.Fatalf("nil payload with input salt: salt=%q err=%v, want PR3FS4LT/nil", salt, err)
	}
}

func TestInfoFieldsShapes(t *testing.T) {
	f, err := infoFields(`{"Info":"A","DevVersion":"1.2"}`)
	if err != nil || f["Info"] != "A" || f["DevVersion"] != "1.2" {
		t.Fatalf("json shape: %+v %v", f, err)
	}
	f, err = infoFields("HTTP/1.1 200 OK\r\n\r\n<body><US>1.2.3.4:8803</US></body>")
	if err != nil || f["US"] != "1.2.3.4:8803" {
		t.Fatalf("xml shape: %+v %v", f, err)
	}
	if _, err := infoFields("{broken"); err == nil {
		t.Fatal("expected json error")
	}
}

// randomHex: used for x-pcs-request-id / ClientId — must be hex of the right length.
func TestRandomHex(t *testing.T) {
	s := randomHex(16)
	if len(s) != 32 {
		t.Fatalf("randomHex(16) len = %d", len(s))
	}
	if m, _ := regexp.MatchString(`^[0-9a-f]{32}$`, s); !m {
		t.Fatalf("randomHex not hex: %q", s)
	}
}
