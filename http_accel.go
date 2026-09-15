package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// HTTP Accelerator — parallel Range-request fetch for port-80 web UI files.
//
// Problem: the Dahua relay path is window-limited (PTCP window=64KB, relay
// RTT ~1000ms) yielding ~59 KB/s per realm. A single 1.5 MB ext-all.js
// takes ~25 seconds.
//
// Solution: the camera's embedded HTTP server advertises Accept-Ranges:bytes.
// We intercept GET requests on port 80, split the file into N chunks, open N
// realms in parallel (already pre-bound in the pool), fetch each chunk via
// Range, reassemble in order, and return the assembled response to the
// browser. N=5 realms → ~5×59 = ~295 KB/s → same file in ~5 seconds.
//
// Falls back gracefully:
//   - non-GET requests or requests with existing Range header → normal path
//   - file smaller than accelThreshold                         → normal path
//   - probe fails or no Content-Range / Content-Length         → normal path
//   - server returns 200 instead of 206                        → normal path
//   - any chunk fetch error                                    → normal path
// ---------------------------------------------------------------------------

const (
	accelThreshold  = 128 * 1024       // min file size to bother (128 KB)
	accelWorkers    = 5                // parallel Range slots
	accelChunkLimit = 300 * 1024       // max bytes per chunk (300 KB)
	accelChunkTO    = 30 * time.Second // per-chunk read deadline
)

var (
	accelSizeMu    sync.RWMutex
	accelSizeCache = make(map[string]int64)
)

// httpAccelResult carries the outcome of httpAccelHandler.
type httpAccelResult struct {
	handled     bool     // true = request was fully handled; caller must return
	replacement net.Conn // non-nil = use this conn instead of the original
}

// httpAccelHandler is called from handleBind for port-80 connections.
// It peeks at the first bytes of the TCP connection to decide if the request
// should be accelerated.
//
// Return semantics:
//   - handled=true  → request served; caller must return immediately.
//   - handled=false → caller continues with normal handleBind. If
//     replacement is non-nil the caller must use it instead of ac.conn so
//     that any bytes already buffered in the peekConn are not lost.
func (t *Tunnel) httpAccelHandler(conn net.Conn) httpAccelResult {
	// Use a short read deadline to capture the HTTP request line & headers.
	// Browsers send the request immediately on connection.
	conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	var prefix bytes.Buffer
	tmp := make([]byte, 4096)

	for {
		n, err := conn.Read(tmp)
		if n > 0 {
			prefix.Write(tmp[:n])
			if bytes.Contains(prefix.Bytes(), []byte("\r\n\r\n")) {
				break
			}
			if prefix.Len() > 65536 {
				break
			}
		}
		if err != nil {
			break
		}
	}
	conn.SetReadDeadline(time.Time{})

	makeReplay := func() net.Conn {
		if prefix.Len() == 0 {
			return conn
		}
		b := prefix.Bytes()
		bufCopy := make([]byte, len(b))
		copy(bufCopy, b)
		return &replayConn{Conn: conn, r: io.MultiReader(bytes.NewReader(bufCopy), conn)}
	}

	if prefix.Len() == 0 {
		return httpAccelResult{replacement: conn}
	}

	// Parse the captured HTTP request.
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(prefix.Bytes())))
	if err != nil {
		return httpAccelResult{replacement: makeReplay()}
	}

	// Only accelerate simple GET requests without an explicit Range header.
	if req.Method != "GET" || req.Header.Get("Range") != "" {
		return httpAccelResult{replacement: makeReplay()}
	}

	path := req.URL.Path
	cl, ok := t.accelProbeSize(path)
	if !ok || cl < accelThreshold {
		return httpAccelResult{replacement: makeReplay()}
	}

	t.logf("accel: %s size=%d, launching %d parallel Range workers", path, cl, accelWorkers)

	body, contentType, err := t.accelFetch(path, cl)
	if err != nil {
		t.logf("accel: fetch failed (%v), falling back to normal path", err)
		return httpAccelResult{replacement: makeReplay()}
	}

	// Write assembled HTTP response to the browser connection.
	resp := fmt.Sprintf(
		"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nContent-Type: %s\r\nConnection: close\r\nAccept-Ranges: bytes\r\n\r\n",
		len(body), contentType,
	)
	conn.Write([]byte(resp))
	conn.Write(body)
	conn.Close()

	t.logf("accel: %s delivered %d bytes to browser", path, len(body))
	return httpAccelResult{handled: true}
}

// accelProbeSize issues a probe Range 0-0 to discover Content-Length.
// Results are cached in memory to eliminate redundant probes.
func (t *Tunnel) accelProbeSize(path string) (int64, bool) {
	accelSizeMu.RLock()
	if cached, ok := accelSizeCache[path]; ok {
		accelSizeMu.RUnlock()
		if cached <= 0 {
			return 0, false
		}
		return cached, true
	}
	accelSizeMu.RUnlock()

	body, err := t.accelDoRangeRequest(path, 0, 0)
	if err != nil || body.status != 206 || body.totalSize <= 0 {
		accelSizeMu.Lock()
		accelSizeCache[path] = -1
		accelSizeMu.Unlock()
		return 0, false
	}

	accelSizeMu.Lock()
	accelSizeCache[path] = body.totalSize
	accelSizeMu.Unlock()

	return body.totalSize, true
}

// accelFetch splits the file into chunks and fetches them concurrently using
// up to accelWorkers parallel connections.
func (t *Tunnel) accelFetch(path string, totalSize int64) ([]byte, string, error) {
	type chunk struct {
		start, end int64
		idx        int
	}
	var chunks []chunk
	var pos int64
	idx := 0
	for pos < totalSize {
		end := pos + accelChunkLimit - 1
		if end >= totalSize {
			end = totalSize - 1
		}
		chunks = append(chunks, chunk{start: pos, end: end, idx: idx})
		pos = end + 1
		idx++
	}

	results := make([][]byte, len(chunks))
	var contentType string
	var mu sync.Mutex
	var fetchErr error

	sem := make(chan struct{}, accelWorkers)
	var wg sync.WaitGroup

	for _, ch := range chunks {
		select {
		case sem <- struct{}{}:
		case <-t.done:
			return nil, "", fmt.Errorf("tunnel closed")
		}

		mu.Lock()
		if fetchErr != nil {
			mu.Unlock()
			<-sem
			break
		}
		mu.Unlock()

		wg.Add(1)
		go func(c chunk) {
			defer wg.Done()
			defer func() { <-sem }()

			result, err := t.accelDoRangeRequest(path, c.start, c.end)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if fetchErr == nil {
					fetchErr = fmt.Errorf("chunk %d [%d-%d]: %v", c.idx, c.start, c.end, err)
				}
				return
			}
			if result.status != 206 {
				if fetchErr == nil {
					fetchErr = fmt.Errorf("chunk %d: got status %d, not 206", c.idx, result.status)
				}
				return
			}
			results[c.idx] = result.body
			if contentType == "" && result.contentType != "" {
				contentType = result.contentType
			}
		}(ch)
	}
	wg.Wait()

	if fetchErr != nil {
		return nil, "", fetchErr
	}

	// Assemble chunks in order.
	var buf bytes.Buffer
	for _, part := range results {
		buf.Write(part)
	}
	if contentType == "" {
		contentType = mimeByExt(path)
	}
	return buf.Bytes(), contentType, nil
}

// accelRangeResult holds the result of one Range fetch.
type accelRangeResult struct {
	status      int
	body        []byte
	contentType string
	totalSize   int64
}

// accelDoRangeRequest opens a fresh realm, sends an HTTP GET with a Range
// header, reads the 206 response body, and returns it.
func (t *Tunnel) accelDoRangeRequest(path string, start, end int64) (*accelRangeResult, error) {
	realmID, bound := t.popRealm(80)
	if !bound {
		// No pre-bound realm available; bind fresh.
		realmID = rand.Uint32()
		if err := t.accelBindRealm(realmID, 80); err != nil {
			return nil, fmt.Errorf("bind realm: %v", err)
		}
	}

	// Register a buffered data channel for this realm.
	dataCh := make(chan []byte, 2048)
	t.scanMu.Lock()
	t.scanResults[realmID] = dataCh
	t.scanMu.Unlock()

	defer func() {
		t.scanMu.Lock()
		delete(t.scanResults, realmID)
		t.scanMu.Unlock()
		// Send DISC to clean up on camera side.
		if p := t.getPrimary(); p != nil && !t.useTCPPath {
			disc := make([]byte, 16)
			disc[0] = 0x12
			binary.BigEndian.PutUint32(disc[4:8], realmID)
			copy(disc[12:], "DISC")
			p.RequestPTCP(disc)
		}
	}()

	// Send the HTTP GET with Range header through the realm.
	req := fmt.Sprintf(
		"GET %s HTTP/1.1\r\nHost: 127.0.0.1\r\nRange: bytes=%d-%d\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n",
		path, start, end,
	)
	t.writeRealmData(realmID, []byte(req))

	// Collect response bytes until complete, connection closes (DISC), or timeout.
	deadline := time.Now().Add(accelChunkTO)
	var respBuf bytes.Buffer

	for time.Now().Before(deadline) {
		select {
		case payload, ok := <-dataCh:
			if !ok || len(payload) == 0 {
				goto parse
			}
			respBuf.Write(payload)
			if isHTTPResponseComplete(respBuf.Bytes(), start, end) {
				goto parse
			}
		case <-time.After(500 * time.Millisecond):
			// Check if DISC arrived (realm deleted).
			t.scanMu.Lock()
			still := t.scanResults[realmID] != nil
			t.scanMu.Unlock()
			if !still {
				goto parse
			}
		case <-t.done:
			return nil, fmt.Errorf("tunnel closed")
		}
	}

parse:
	raw := respBuf.Bytes()
	if len(raw) == 0 {
		return nil, fmt.Errorf("no response data for [%d-%d]", start, end)
	}

	return parseHTTPRangeResponse(raw, path)
}

// accelBindRealm sends a BIND packet and waits for the 0x12 CONN.
func (t *Tunnel) accelBindRealm(realmID uint32, remotePort int) error {
	wait := make(chan struct{}, 1)
	t.bindMu.Lock()
	t.bindWait[realmID] = wait
	t.bindMu.Unlock()

	bindPkt := make([]byte, 20)
	bindPkt[0] = 0x11
	binary.BigEndian.PutUint32(bindPkt[4:8], realmID)
	binary.BigEndian.PutUint32(bindPkt[12:16], uint32(remotePort))
	bindPkt[16] = 0x7F
	bindPkt[19] = 0x01

	ticker := time.NewTicker(400 * time.Millisecond)
	defer ticker.Stop()
	timer := time.NewTimer(BIND_TIMEOUT)
	defer timer.Stop()

	t.bindReqMu.Lock()
	if p := t.getPrimary(); p != nil {
		p.RequestPTCP(bindPkt)
	}
	time.Sleep(10 * time.Millisecond)
	t.bindReqMu.Unlock()

	for {
		select {
		case <-wait:
			return nil
		case <-ticker.C:
			t.bindReqMu.Lock()
			if p := t.getPrimary(); p != nil {
				p.RequestPTCP(bindPkt)
			}
			t.bindReqMu.Unlock()
		case <-timer.C:
			t.takeBindWait(realmID)
			return fmt.Errorf("bind timeout for realm %#010x port %d", realmID, remotePort)
		case <-t.done:
			t.takeBindWait(realmID)
			return fmt.Errorf("tunnel closed during bind")
		}
	}
}

// isHTTPResponseComplete checks if we have received a complete HTTP response.
func isHTTPResponseComplete(data []byte, start, end int64) bool {
	idx := bytes.Index(data, []byte("\r\n\r\n"))
	if idx < 0 {
		return false
	}
	headers := string(data[:idx])
	actualBody := int64(len(data) - idx - 4)

	// If status is 206, expected size is exactly end - start + 1
	if strings.Contains(headers, " 206 ") {
		return actualBody >= (end - start + 1)
	}

	// For other statuses, parse Content-Length if present
	for _, line := range strings.Split(headers, "\r\n") {
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "content-length:") {
			val := strings.TrimSpace(line[len("content-length:"):])
			if cl, err := strconv.ParseInt(val, 10, 64); err == nil {
				return actualBody >= cl
			}
		}
	}
	return false
}

// parseHTTPRangeResponse extracts status, headers, and body from a raw HTTP response.
func parseHTTPRangeResponse(raw []byte, path string) (*accelRangeResult, error) {
	r := bufio.NewReader(bytes.NewReader(raw))
	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		return nil, fmt.Errorf("parse response: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, fmt.Errorf("read body: %v", err)
	}

	totalSize := int64(0)
	cr := resp.Header.Get("Content-Range")
	if cr != "" {
		// e.g. "bytes 0-1023/1497654"
		if idx := strings.LastIndex(cr, "/"); idx >= 0 {
			totalSize, _ = strconv.ParseInt(cr[idx+1:], 10, 64)
		}
	}

	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		// Dahua firmware typo: "Contene-Type"
		ct = resp.Header.Get("Contene-Type")
	}
	if ct == "" {
		ct = mimeByExt(path)
	}

	return &accelRangeResult{
		status:      resp.StatusCode,
		body:        body,
		contentType: ct,
		totalSize:   totalSize,
	}, nil
}

// mimeByExt infers Content-Type from common web asset extensions.
func mimeByExt(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".js":
		return "application/javascript"
	case ".css":
		return "text/css"
	case ".html", ".htm":
		return "text/html"
	case ".json":
		return "application/json"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	case ".svg":
		return "image/svg+xml"
	case ".woff":
		return "font/woff"
	case ".woff2":
		return "font/woff2"
	case ".ttf":
		return "font/ttf"
	default:
		return "application/octet-stream"
	}
}

// replayConn wraps a net.Conn with an io.Reader (typically io.MultiReader)
// so bytes read during HTTP inspection are seamlessly replayed before
// reading live from the underlying socket.
type replayConn struct {
	net.Conn
	r io.Reader
}

func (p *replayConn) Read(b []byte) (int, error) {
	return p.r.Read(b)
}

// peekConn wraps a net.Conn with a bufio.Reader.
type peekConn struct {
	net.Conn
	br *bufio.Reader
}

func (p *peekConn) Read(b []byte) (int, error) {
	return p.br.Read(b)
}
