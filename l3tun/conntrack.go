package l3tun

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// conntrackMgr manages per-flow authentication tokens for the L3 tunnel.
//
// Before the first packet of a flow (5-tuple) can be sent through the
// L3 tunnel, an auth exchange (HMAC-SHA256-signed JSON) must complete
// to obtain a connectToken.
//
// Flow:
//
//	WritePacket → ensureToken → (if new) DoAuth sends frame on conn
//	            → blocks on done chan
//	readLoop receives 0x93 → handleAuthResp → markAuth(authID, token)
//	            → close(done) → ensureToken returns token
//
// The authID mapping allows the async response handler to find the flow entry
// identified by the server-returned conntrackHash.
type conntrackMgr struct {
	mu      sync.Mutex
	entries map[string]*conntrackEntry

	// authID → entry for async response lookup.
	byAuthID   map[uint64]*conntrackEntry
	nextAuthID uint64

	// DoAuth sends the per-flow auth request frame on the given conn.
	// It must NOT block — the caller (ensureToken) handles waiting.
	// Set by the L3 tunnel during initialization.
	DoAuth func(c *conn, authID uint64,
		srcIP net.IP, srcPort uint16,
		dstIP net.IP, dstPort uint16,
		proto uint8, appID string) error
}

type conntrackEntry struct {
	authID uint64
	token  string
	err    error
	done   chan struct{}

	// started guards the one-shot DoAuth call.
	started atomic.Bool
}

const authTimeout = 8 * time.Second

func newConntrackMgr() *conntrackMgr {
	return &conntrackMgr{
		entries:  make(map[string]*conntrackEntry),
		byAuthID: make(map[uint64]*conntrackEntry),
	}
}

func connTrackKey(atyp uint8, srcIP net.IP, srcPort uint16,
	dstIP net.IP, dstPort uint16) string {
	return fmt.Sprintf("%d:%s:%d-%s:%d",
		atyp, srcIP, srcPort, dstIP, dstPort)
}

// ensureToken returns the connect token for a flow, triggering
// per-flow auth on the given conn if this is the first packet.
func (m *conntrackMgr) ensureToken(
	c *conn,
	atyp uint8,
	srcIP net.IP, srcPort uint16,
	dstIP net.IP, dstPort uint16,
	proto uint8,
	appID string,
) (string, error) {
	key := connTrackKey(atyp, srcIP, srcPort, dstIP, dstPort)

	m.mu.Lock()
	entry, exists := m.entries[key]
	if !exists {
		authID := atomic.AddUint64(&m.nextAuthID, 1)
		entry = &conntrackEntry{
			authID: authID,
			done:   make(chan struct{}),
		}
		m.entries[key] = entry
		m.byAuthID[authID] = entry
	}
	m.mu.Unlock()

	// Already resolved — return immediately.
	if entry.started.Load() {
		return entry.wait(key)
	}

	// First caller: send auth request then wait for async response.
	if entry.started.CompareAndSwap(false, true) {
		if m.DoAuth != nil {
			if err := m.DoAuth(c, entry.authID,
				srcIP, srcPort, dstIP, dstPort, proto, appID); err != nil {
				// Send failed — mark immediately.
				entry.err = fmt.Errorf("per-flow auth send: %w", err)
				close(entry.done)
			}
		} else {
			entry.err = fmt.Errorf("DoAuth not configured")
			close(entry.done)
		}
	}

	return entry.wait(key)
}

func (e *conntrackEntry) wait(key string) (string, error) {
	select {
	case <-e.done:
		return e.token, e.err
	case <-time.After(authTimeout):
		return "", fmt.Errorf("per-flow auth timeout for %s", key)
	}
}

// markAuth resolves a pending auth from the async response handler.
//
// authID is the server-returned conntrackHash, which was set as the
// authID when the entry was created.
func (m *conntrackMgr) markAuth(authID uint64, token string, err error) {
	m.mu.Lock()
	entry := m.byAuthID[authID]
	if entry != nil && token != "" {
		entry.token = token
	}
	m.mu.Unlock()

	if entry == nil {
		return
	}
	entry.err = err

	// Close channel if not already closed.
	select {
	case <-entry.done:
		return
	default:
		close(entry.done)
	}
}
