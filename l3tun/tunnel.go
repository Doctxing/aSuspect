// Package l3tun implements the L3 tunnel — shared TLS connection with
// per-flow authentication (conntrack) and binary frame multiplexing.
// gVisor userspace TCP/IP stack runs on top.
package l3tun

import (
	"bufio"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"sync"

	"aSuspect/spa"
)

// ── tunnel ───────────────────────────────────────────────────────────────────

// tunnel manages L3 connections to aTrust nodes and provides
// a raw IP packet I/O interface.  gVisor runs on top.
type tunnel struct {
	state   clientInfo
	signKey []byte

	// SpaExt is pre-computed SPA ClientHello extension data.
	// When set, TLS dials inject it into the ClientHello.
	SpaExt []byte

	conns   map[string]*conn // node address → TLS conn
	connsMu sync.Mutex
	dialing map[string]*dialWait
	closed  bool

	// Incoming packets from all connections → gVisor.
	Incoming chan []byte

	conntrack *conntrackMgr
	OnVIP     func([]net.IP)
}

type clientInfo struct {
	sid          string
	deviceID     string
	connectionID string
	username     string
}

type conn struct {
	tls     net.Conn
	reader  *bufio.Reader
	writeMu sync.Mutex
	closeCh chan struct{}
	once    sync.Once
	addr    string
}

type dialWait struct {
	done chan struct{}
	conn *conn
	err  error
}

// newTunnel creates an L3 tunnel manager.
func newTunnel(sid, deviceID, connectionID, username, signKeyHex string) (*tunnel, error) {
	signKey, err := hex.DecodeString(signKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid sign key: %w", err)
	}

	t := &tunnel{
		state: clientInfo{
			sid: sid, deviceID: deviceID,
			connectionID: connectionID, username: username,
		},
		signKey:   signKey,
		conns:     make(map[string]*conn),
		dialing:   make(map[string]*dialWait),
		Incoming:  make(chan []byte, 4096),
		conntrack: newConntrackMgr(),
	}

	// Wire up per-flow auth — DoAuth sends the frame on the active conn
	// and returns immediately; the async response is handled by
	// readLoop → handleAuthResp → markAuth.
	t.conntrack.DoAuth = func(c *conn, authID uint64,
		srcIP net.IP, srcPort uint16,
		dstIP net.IP, dstPort uint16,
		proto uint8, appID string,
	) error {
		return t.sendPerFlowAuth(c, authID, srcIP, srcPort, dstIP, dstPort, proto, appID)
	}

	return t, nil
}

// EnsureConn returns a TLS connection for the given node address,
// creating one if necessary.
func (t *tunnel) EnsureConn(nodeAddr string) (*conn, error) {
	t.connsMu.Lock()
	if t.closed {
		t.connsMu.Unlock()
		return nil, fmt.Errorf("L3 tunnel closed")
	}
	if c, ok := t.conns[nodeAddr]; ok {
		t.connsMu.Unlock()
		return c, nil
	}
	if wait, ok := t.dialing[nodeAddr]; ok {
		t.connsMu.Unlock()
		<-wait.done
		return wait.conn, wait.err
	}

	wait := &dialWait{done: make(chan struct{})}
	t.dialing[nodeAddr] = wait
	t.connsMu.Unlock()

	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	rawConn, err := spa.DialTLS(nodeAddr, tlsConfig, t.SpaExt)
	if err != nil {
		t.finishDial(nodeAddr, wait, nil, err)
		return nil, err
	}

	c := &conn{
		tls:     rawConn,
		reader:  bufio.NewReader(rawConn),
		closeCh: make(chan struct{}),
		addr:    nodeAddr,
	}

	// tunnel-level auth.
	if err := t.authTunnel(c); err != nil {
		rawConn.Close()
		err = fmt.Errorf("L3 tunnel auth: %w", err)
		t.finishDial(nodeAddr, wait, nil, err)
		return nil, err
	}

	c = t.finishDial(nodeAddr, wait, c, nil)
	return c, nil
}

func (t *tunnel) finishDial(nodeAddr string, wait *dialWait, c *conn, err error) *conn {
	t.connsMu.Lock()
	defer t.connsMu.Unlock()

	if t.dialing[nodeAddr] == wait {
		delete(t.dialing, nodeAddr)
	}

	if err == nil && t.closed {
		c.close()
		err = fmt.Errorf("L3 tunnel closed")
		c = nil
	}

	if err == nil {
		if existing, ok := t.conns[nodeAddr]; ok {
			c.close()
			c = existing
		} else {
			t.conns[nodeAddr] = c
			go t.readLoop(c)
			go t.heartbeatLoop(c)
		}
	}

	wait.conn = c
	wait.err = err
	close(wait.done)
	return c
}

// WritePacket sends a raw IPv4 packet through the L3 tunnel for a specific flow.
func (t *tunnel) WritePacket(
	c *conn,
	srcIP net.IP, srcPort uint16,
	dstIP net.IP, dstPort uint16,
	proto uint8,
	appID string,
	packet []byte,
) error {
	// Ensure per-flow authentication (blocks until auth completes).
	token, err := t.conntrack.ensureToken(c, 4,
		srcIP, srcPort, dstIP, dstPort, proto, appID)
	if err != nil {
		return fmt.Errorf("conntrack: %w", err)
	}

	payload := buildDataFrame(token, [][]byte{packet})
	return c.writeFrame(payload)
}

// EvictConn removes a connection from the pool (called on read error).
func (t *tunnel) EvictConn(c *conn) {
	t.connsMu.Lock()
	if existing, ok := t.conns[c.addr]; ok && existing == c {
		delete(t.conns, c.addr)
	}
	t.connsMu.Unlock()
}

// Close shuts down all connections.
func (t *tunnel) Close() {
	t.connsMu.Lock()
	defer t.connsMu.Unlock()
	if t.closed {
		return
	}
	t.closed = true
	for _, c := range t.conns {
		c.close()
	}
	t.conns = make(map[string]*conn)
}

// ── Conn helpers ─────────────────────────────────────────────────────────────

func (c *conn) writeFrame(data []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_, err := c.tls.Write(data)
	return err
}

// WriteRaw sends raw bytes directly on the TLS connection.
// Exported for DNS resolver and other direct-write paths.
func (c *conn) WriteRaw(data []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_, err := c.tls.Write(data)
	return err
}

func (c *conn) close() {
	c.once.Do(func() {
		close(c.closeCh)
		c.tls.Close()
	})
}
