package main

import (
	"bufio"
	"io"
	"net"
	"testing"
)

func TestMimeByExt(t *testing.T) {
	cases := []struct {
		path     string
		expected string
	}{
		{"/ext/ext-all.js", "application/javascript"},
		{"/css/style.css", "text/css"},
		{"/index.html", "text/html"},
		{"/images/logo.png", "image/png"},
		{"/data.json", "application/json"},
		{"/unknown.xyz", "application/octet-stream"},
	}

	for _, tc := range cases {
		got := mimeByExt(tc.path)
		if got != tc.expected {
			t.Errorf("mimeByExt(%q) = %q, want %q", tc.path, got, tc.expected)
		}
	}
}

func TestIsHTTPResponseComplete(t *testing.T) {
	// 206 with exact range
	resp206 := "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-4/10\r\n\r\nhello"
	if !isHTTPResponseComplete([]byte(resp206), 0, 4) {
		t.Errorf("expected resp206 to be complete")
	}

	// 206 with incomplete body
	resp206Short := "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-4/10\r\n\r\nhel"
	if isHTTPResponseComplete([]byte(resp206Short), 0, 4) {
		t.Errorf("expected resp206Short to NOT be complete")
	}

	// 200 with Content-Length
	resp200 := "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n1234"
	if !isHTTPResponseComplete([]byte(resp200), 0, 100) {
		t.Errorf("expected resp200 with Content-Length to be complete")
	}

	// 200 with partial body
	resp200Short := "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n12"
	if isHTTPResponseComplete([]byte(resp200Short), 0, 100) {
		t.Errorf("expected resp200Short to NOT be complete")
	}
}

func TestParseHTTPRangeResponse(t *testing.T) {
	// Dahua firmware typo "Contene-Type"
	raw := "HTTP/1.1 206 Partial Content\r\n" +
		"Content-Length: 10\r\n" +
		"Content-Range: bytes 0-9/1000\r\n" +
		"Contene-Type: application/x-javascript\r\n\r\n" +
		"0123456789"

	res, err := parseHTTPRangeResponse([]byte(raw), "/test.js")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.status != 206 {
		t.Errorf("got status %d, want 206", res.status)
	}
	if res.totalSize != 1000 {
		t.Errorf("got totalSize %d, want 1000", res.totalSize)
	}
	if res.contentType != "application/x-javascript" {
		t.Errorf("got contentType %q, want application/x-javascript", res.contentType)
	}
	if string(res.body) != "0123456789" {
		t.Errorf("got body %q, want 0123456789", string(res.body))
	}
}

func TestPeekConn(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()

	go func() {
		c2.Write([]byte("prefix_suffix"))
		c2.Close()
	}()

	br := bufio.NewReader(c1)
	peeked, err := br.Peek(7)
	if err != nil {
		t.Fatalf("peek error: %v", err)
	}
	if string(peeked) != "prefix_" {
		t.Fatalf("peeked %q, want prefix_", string(peeked))
	}

	pc := &peekConn{Conn: c1, br: br}
	all, err := io.ReadAll(pc)
	if err != nil {
		t.Fatalf("read all error: %v", err)
	}
	if string(all) != "prefix_suffix" {
		t.Fatalf("got %q, want prefix_suffix", string(all))
	}
}

func TestPeekConnDrainsBuffer(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()

	go func() {
		c2.Write([]byte("abcdefghij"))
		c2.Close()
	}()

	br := bufio.NewReader(c1)
	// Consume first 4 bytes via bufio
	buf4 := make([]byte, 4)
	if _, err := io.ReadFull(br, buf4); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(buf4) != "abcd" {
		t.Fatalf("got %q, want abcd", string(buf4))
	}

	// Wrap in peekConn
	pc := &peekConn{Conn: c1, br: br}
	rest, err := io.ReadAll(pc)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}
	if string(rest) != "efghij" {
		t.Fatalf("got %q, want efghij", string(rest))
	}
}

func TestHTTPAccelFallbackOnNonGET(t *testing.T) {
	tun := &Tunnel{
		done: make(chan struct{}),
	}

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	go func() {
		c2.Write([]byte("POST /login HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"))
	}()

	res := tun.httpAccelHandler(c1)
	if res.handled {
		t.Errorf("expected handled to be false for POST")
	}
	if res.replacement == nil {
		t.Fatalf("expected non-nil replacement conn")
	}

	// Read from replacement conn to verify bytes weren't lost
	buf := make([]byte, 4)
	n, err := res.replacement.Read(buf)
	if err != nil {
		t.Fatalf("read from replacement failed: %v", err)
	}
	if string(buf[:n]) != "POST" {
		t.Errorf("read %q, want POST", string(buf[:n]))
	}
}

func TestHTTPAccelFallbackOnRangeHeader(t *testing.T) {
	tun := &Tunnel{
		done: make(chan struct{}),
	}

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	go func() {
		c2.Write([]byte("GET /test.js HTTP/1.1\r\nHost: 127.0.0.1\r\nRange: bytes=0-10\r\n\r\n"))
	}()

	res := tun.httpAccelHandler(c1)
	if res.handled {
		t.Errorf("expected handled to be false for request with Range header")
	}
	if res.replacement == nil {
		t.Fatalf("expected non-nil replacement conn")
	}
}

func TestHTTPAccelProbeCache(t *testing.T) {
	tun := &Tunnel{
		done: make(chan struct{}),
	}

	// Seed cache
	accelSizeMu.Lock()
	accelSizeCache["/cached-asset.js"] = 500000
	accelSizeMu.Unlock()

	size, ok := tun.accelProbeSize("/cached-asset.js")
	if !ok || size != 500000 {
		t.Errorf("expected cache hit with size 500000, got (%d, %v)", size, ok)
	}

	// Seed not found
	accelSizeMu.Lock()
	accelSizeCache["/missing.js"] = -1
	accelSizeMu.Unlock()

	_, ok = tun.accelProbeSize("/missing.js")
	if ok {
		t.Errorf("expected cache hit for -1 to return ok=false")
	}
}
