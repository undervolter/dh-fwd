package main

import (
	"net"
	"strings"
	"testing"
)

// Unit tests for the CSV LocalAddr builder (tunnel.go). The CSV is the
// DMSS app's wire form and is kept for app parity: the earlier "single-entry
// → 403" live bracket (2026-09-06: bare "host:port" → 403
// DevPwd_InvalidDigest, app-format CSV → 200) ran with dh-fwd's header
// serialization and is confounded — live evidence later showed the header
// serialization was the discriminator, not the CSV shape. The builder's
// contract stays as shipped: bare-IP prefixes, exactly one final
// "bindIP:port" entry, at least one prefix guaranteed.

// The CSV ends in "bindIP:port" and every earlier entry is a bare IP.
func TestBuildLocalAddrCSVShape(t *testing.T) {
	got := buildLocalAddr([]string{"10.8.0.2", "192.168.1.10"}, "192.168.1.10", 50000)
	want := "10.8.0.2,192.168.1.10,192.168.1.10:50000"
	if got != want {
		t.Fatalf("buildLocalAddr = %q, want %q", got, want)
	}
	idx := strings.LastIndex(got, ",")
	if idx < 0 {
		t.Fatalf("no CSV separator: %q", got)
	}
	last := got[idx+1:]
	if last != "192.168.1.10:50000" {
		t.Fatalf("final entry = %q, want the bind host:port", last)
	}
	for _, p := range strings.Split(got[:idx], ",") {
		if strings.Contains(p, ":") {
			t.Fatalf("prefix %q carries a port — prefixes are bare IPs: %q", p, got)
		}
		if net.ParseIP(p) == nil || net.ParseIP(p).To4() == nil {
			t.Fatalf("prefix %q is not an IPv4 literal: %q", p, got)
		}
	}
}

// The ≥1-prefix guarantee: with no other interface IPv4 available, the bind
// IP doubles as the prefix — "bind,bind:port" (duplicate is parse-safe).
func TestBuildLocalAddrGuaranteesPrefix(t *testing.T) {
	for _, prefixes := range [][]string{nil, {}} {
		got := buildLocalAddr(prefixes, "192.168.1.10", 50000)
		want := "192.168.1.10,192.168.1.10:50000"
		if got != want {
			t.Fatalf("buildLocalAddr(%v) = %q, want fallback %q", prefixes, got, want)
		}
		parts := strings.Split(got, ",")
		if len(parts) != 2 || parts[0] != "192.168.1.10" {
			t.Fatalf("fallback shape broken: %q", got)
		}
	}
	// Never emits a bare host:port — the CSV always carries at least one
	// bare-IP prefix entry.
	if !strings.Contains(buildLocalAddr(nil, "192.168.1.10", 50000), ",") {
		t.Fatal("builder emitted a prefix-less LocalAddr")
	}
}

// localAddrPrefixes must never surface loopback, IPv4 link-local
// (169.254.0.0/16), the bind IP itself, or anything that is not a bare
// IPv4 literal — whatever the host's interface table looks like.
func TestLocalAddrPrefixesExclusions(t *testing.T) {
	bind := "203.0.113.7" // TEST-NET-3: never assigned to a real interface
	prefixes := localAddrPrefixes(bind)
	seen := map[string]bool{}
	for _, p := range prefixes {
		if seen[p] {
			t.Fatalf("duplicate prefix %q: %v", p, prefixes)
		}
		seen[p] = true
		ip := net.ParseIP(p)
		if ip == nil || ip.To4() == nil || strings.Contains(p, ":") {
			t.Fatalf("prefix %q is not a bare IPv4 literal", p)
		}
		if ip.IsLoopback() {
			t.Fatalf("loopback %q leaked into prefixes", p)
		}
		if ip.IsLinkLocalUnicast() {
			t.Fatalf("link-local %q leaked into prefixes", p)
		}
		if p == bind {
			t.Fatalf("bind IP %q duplicated as a prefix", p)
		}
	}
}

// End to end through the request: localAddr() is the CSV with the socket's
// bind as the final entry and the enumerated interfaces as prefixes.
func TestChannelRequestLocalAddrCSV(t *testing.T) {
	cr := newChannelRequest(dmssProfile, 1, "admin", "pass123", "Rs4lt",
		[]byte{1, 2, 3, 4, 5, 6, 7, 8}, "127.0.0.1", 50000, 554)

	// The enumeration never surfaces loopback/link-local/bind.
	for _, p := range cr.addrPrefixes {
		ip := net.ParseIP(p)
		if ip == nil || ip.To4() == nil {
			t.Fatalf("prefix %q is not a bare IPv4", p)
		}
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			t.Fatalf("prefix %q is loopback/link-local/unspecified", p)
		}
	}

	got := cr.localAddr()
	parts := strings.Split(got, ",")
	if last := parts[len(parts)-1]; last != "127.0.0.1:50000" {
		t.Fatalf("final entry = %q, want the bind host:port 127.0.0.1:50000", last)
	}
	// The ≥1-prefix guarantee: the rendered prefixes are the enumerated
	// list, or the bind doubling as the fallback prefix on a host with no
	// other IPv4 (a loopback bind makes that duplicate a loopback entry by
	// construction — accepted there, never via the enumeration).
	wantPrefixes := cr.addrPrefixes
	if len(wantPrefixes) == 0 {
		wantPrefixes = []string{cr.bindIP}
	}
	if len(parts) != len(wantPrefixes)+1 {
		t.Fatalf("localAddr = %q, want %d prefixes + bind entry", got, len(wantPrefixes))
	}
	if gotPrefixes := strings.Join(parts[:len(parts)-1], ","); gotPrefixes != strings.Join(wantPrefixes, ",") {
		t.Fatalf("rendered prefixes %q != expected %q", gotPrefixes, strings.Join(wantPrefixes, ","))
	}
}
