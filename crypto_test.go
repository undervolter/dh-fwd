package main

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// Golden vectors computed independently of the Go code (python3 hashlib /
// openssl enc -aes-256-ofb) from the protocol formulas — fact #1 (WSSE
// digest) and dh-p2p PR#29/#33 (Type-1 auth crypto).

func TestWSSEDigestGolden(t *testing.T) {
	tests := []struct {
		name   string
		nonce  string
		creatd string
		user   string
		key    string
		want   string
	}{
		{
			name:   "dmss pair",
			nonce:  "42",
			creatd: "2026-09-06T12:00:00+03:00",
			user:   DMSS_WSSE_USERNAME,
			key:    DMSS_WSSE_USERKEY,
			want:   "VSIOT9Z5Ht/rmuQ677AZ5CzIbOk=",
		},
		{
			name:   "smartpss pair",
			nonce:  "42",
			creatd: "2026-09-06T12:00:00Z",
			user:   WSSE_USERNAME,
			key:    WSSE_USERKEY,
			want:   "2+go9D1pKW5ykn3ePUMZkhMmITo=",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := wsseDigest(tc.nonce, tc.creatd, tc.user, tc.key); got != tc.want {
				t.Fatalf("wsseDigest = %q, want %q", got, tc.want)
			}
		})
	}
}

// The wire digest must be recomputable from the emitted X-WSSE header with
// the documented formula and the profile's own pair — this is what gates
// serial→device resolution on the cloud.
func TestBuildDHRequestDigestMatchesHeader(t *testing.T) {
	for _, prof := range []*appProfile{smartpssProfile, dmssProfile} {
		req := string(buildDHRequest(prof.verbGet, "/online/p2psrv/SN", "", true, 1, prof, "", false))
		user := regexp.MustCompile(`Username="([^"]+)"`).FindStringSubmatch(req)
		digest := regexp.MustCompile(`PasswordDigest="([^"]+)"`).FindStringSubmatch(req)
		nonce := regexp.MustCompile(`Nonce="([^"]+)"`).FindStringSubmatch(req)
		creatd := regexp.MustCompile(`Created="([^"]+)"`).FindStringSubmatch(req)
		if user == nil || digest == nil || nonce == nil || creatd == nil {
			t.Fatalf("%s: X-WSSE header incomplete:\n%s", prof.name, req)
		}
		want := wsseDigest(nonce[1], creatd[1], user[1], prof.wsseUserKey)
		if digest[1] != want {
			t.Fatalf("%s: PasswordDigest %q != recomputed %q", prof.name, digest[1], want)
		}
		if user[1] != prof.wsseUser {
			t.Fatalf("%s: header Username %q != profile pair", prof.name, user[1])
		}
	}
}

func TestGetDeriveKeyGolden(t *testing.T) {
	// MD5hex-UP("admin:Login to Rs4lt:pass123")
	got := string(getDeriveKey("admin", "pass123", "Rs4lt"))
	if got != "E09866C7DE38480830B5C41C3EB39768" {
		t.Fatalf("getDeriveKey = %q", got)
	}
}

func TestDeriveDKGolden(t *testing.T) {
	// PBKDF2-HMAC-SHA256(key, "777", 20000, 32)
	key := []byte("E09866C7DE38480830B5C41C3EB39768")
	got := deriveDK(key, 777)
	want := "b372ad6b00ff576fa244fcb622b5297cbd5bd5050ff7263a3f624ac4460296c6"
	if len(got) != 32 || fmt.Sprintf("%x", got) != want {
		t.Fatalf("deriveDK = %x, want %s", got, want)
	}
}

func TestGetEncGolden(t *testing.T) {
	// AES-256-OFB(IV "2z52*lk9o6HRyJrf") over "127.0.0.1:40000" with the
	// derived key — openssl enc -aes-256-ofb vector. getEnc takes the
	// master key and derives DK = PBKDF2(key, nonce) internally, so the
	// ciphertext below is AES-256-OFB(DK) with DK pinned by
	// TestDeriveDKGolden (verified independently with openssl).
	key := []byte("E09866C7DE38480830B5C41C3EB39768")
	if got := getEnc(key, 777, "127.0.0.1:40000"); got != "/R40Newcuzi0faikzfZA" {
		t.Fatalf("getEnc = %q", got)
	}
}

func TestGetEncDecRoundTrip(t *testing.T) {
	// Round-trip from the MASTER key — the production chain is
	// master → (deriveDK inside getEnc/getDec) → ciphertext — not from a
	// pre-derived DK (which would re-derive a second-generation key and pin
	// nothing of the real path).
	master := []byte("E09866C7DE38480830B5C41C3EB39768")
	for _, addr := range []string{"127.0.0.1:40000", "192.168.0.51:554", "x"} {
		enc := getEnc(master, 777, addr)
		if got := getDec(master, 777, enc); got != addr {
			t.Fatalf("round-trip %q: got %q", addr, got)
		}
		// A different nonce must not decrypt the ciphertext.
		if got := getDec(master, 778, enc); got == addr {
			t.Fatalf("decryption with wrong nonce succeeded for %q", addr)
		}
	}
	// The fixed encryption golden (TestGetEncGolden) decrypts back to its
	// plaintext from the master key alone — master → DK → ciphertext →
	// plaintext pinned end to end.
	if got := getDec(master, 777, "/R40Newcuzi0faikzfZA"); got != "127.0.0.1:40000" {
		t.Fatalf("getDec(master, 777, golden) = %q, want 127.0.0.1:40000", got)
	}
}

// THE SIGNING FIX: DevAuth must cover the ENCRYPTED LocalAddr string
// (dh-p2p PR#29/#33, verified against captured traffic) — not the plaintext.
func TestGetAuthAtCoversEncryptedAddr(t *testing.T) {
	key := []byte("E09866C7DE38480830B5C41C3EB39768")
	enc := "/R40Newcuzi0faikzfZA" // encrypted "127.0.0.1:40000", nonce 777
	block := getAuthAt("admin", key, 777, enc, "Rs4lt", 1700000000)

	devauth := regexp.MustCompile(`<DevAuth>([^<]+)</DevAuth>`).FindStringSubmatch(block)
	if devauth == nil {
		t.Fatalf("no DevAuth in block: %s", block)
	}
	if len(devauth[1]) != 44 {
		t.Fatalf("DevAuth not 44-char base64: %q", devauth[1])
	}
	// Signature over nonce + CreateDate + encrypted LocalAddr.
	if devauth[1] != "t2Cqkm5AuqmP1raemFgKyu6CmoJeIOZIevOQYZbF3gE=" {
		t.Fatalf("DevAuth = %q (want signature over the ENCRYPTED addr)", devauth[1])
	}
	// Sanity: the plaintext signature (dh-fwd's old bug) differs.
	if devauth[1] == "9LWQ1/RY6DvOduVBs8UhiMn8/CB79u14N5s9b/qz8Gg=" {
		t.Fatal("DevAuth matches the plaintext-addr signature — regression")
	}
	// The block carries the fixed CreateDate, not time.Now().
	if !strings.HasPrefix(block, "<CreateDate>1700000000</CreateDate>") {
		t.Fatalf("CreateDate not fixed: %s", block)
	}
	// Empty randsalt falls back to the default salt tag, as upstream.
	if got := getAuthAt("admin", key, 777, enc, "", 1700000000); !strings.Contains(got, "<RandSalt></RandSalt>") {
		t.Fatalf("empty randsalt not rendered: %s", got)
	}
}

func TestGetNonceRange(t *testing.T) {
	// Signed int32 range — the app draws negative nonces too.
	for range 256 {
		if n := getNonce(); n < -(1<<31) || n >= 1<<31 {
			t.Fatalf("nonce out of int32 range: %d", n)
		}
	}
}

// THE CSV FIX (fw 6.7.20002): the Type-1 LocalAddr payload is the app's CSV
// form, not a bare host:port. The CSV is retained for DMSS app parity: the
// earlier "single-entry → 403" live bracket (2026-09-06: loopback → 403,
// single real IP:port → 403, CSV → 200) ran with dh-fwd's header
// serialization and is confounded — later live evidence showed the header
// serialization was the discriminator. The CSV stays (harmless, app-parity);
// a channel body built with a KNOWN key/nonce/created must encrypt exactly
// that CSV, the ciphertext must be the openssl-pinned bytes, and the DevAuth
// must cover the encrypted CSV.
func TestChannelBodyLocalAddrCSVGolden(t *testing.T) {
	cr := newTestChannelRequest(dmssProfile, 1)
	cr.created = 1700000000
	cr.nonce = 777
	cr.laddrEnc = getEnc(cr.key, cr.nonce, cr.localAddr())

	// Pinned plaintext: two interface prefixes + the loopback bind (the
	// newTestChannelRequest fixture) — the exact CSV the device accepts.
	wantPlain := "192.168.1.10,10.8.0.2,127.0.0.1:50000"
	if got := cr.localAddr(); got != wantPlain {
		t.Fatalf("localAddr = %q, want %q", got, wantPlain)
	}

	body := cr.body()
	enc := regexp.MustCompile(`<LocalAddr>([^<]+)</LocalAddr>`).FindStringSubmatch(body)
	if enc == nil {
		t.Fatalf("body has no LocalAddr:\n%s", body)
	}
	// AES-256-OFB(DK) vector — openssl enc -aes-256-ofb with the DK pinned
	// by TestDeriveDKGolden (verified independently with openssl).
	if want := "/RUxNe0Eszi0aa2k0fdAt/DT5jpJHZfKSE2h6nszQKlDw+8oYQ=="; enc[1] != want {
		t.Fatalf("LocalAddr ciphertext = %q, want pinned %q", enc[1], want)
	}
	// The device decrypts to the exact CSV it requires.
	if got := getDec(cr.key, 777, enc[1]); got != wantPlain {
		t.Fatalf("decrypted LocalAddr = %q, want %q", got, wantPlain)
	}
	// DevAuth covers the encrypted CSV (nonce + pinned CreateDate).
	devauth := regexp.MustCompile(`<DevAuth>([^<]+)</DevAuth>`).FindStringSubmatch(body)
	if devauth == nil {
		t.Fatalf("body has no DevAuth:\n%s", body)
	}
	if want := "Ziefve2EE7bCo9XcmxOXgJUpMflIzUkaFIOD3jlpbqg="; devauth[1] != want {
		t.Fatalf("DevAuth = %q, want pinned signature over the encrypted CSV %q", devauth[1], want)
	}
}
