// package peer implements an object used to represent peers in the ipfs network.
package peer

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"time"

	b58 "github.com/maybebtc/keygen/Godeps/_workspace/src/github.com/jbenet/go-base58"
	ma "github.com/maybebtc/keygen/Godeps/_workspace/src/github.com/jbenet/go-multiaddr"
	mh "github.com/maybebtc/keygen/Godeps/_workspace/src/github.com/jbenet/go-multihash"

	ic "github.com/maybebtc/keygen/Godeps/_workspace/src/github.com/jbenet/go-ipfs/crypto"
	u "github.com/maybebtc/keygen/Godeps/_workspace/src/github.com/jbenet/go-ipfs/util"
)

var log = u.Logger("peer")

// ID is a byte slice representing the identity of a peer.
type ID mh.Multihash

// String is utililty function for printing out peer ID strings.
func (id ID) String() string {
	return id.Pretty()
}

// Equal is utililty function for comparing two peer ID's
func (id ID) Equal(other ID) bool {
	return bytes.Equal(id, other)
}

// Pretty returns a b58-encoded string of the ID
func (id ID) Pretty() string {
	return b58.Encode(id)
}

// DecodePrettyID returns a b58-encoded string of the ID
func DecodePrettyID(s string) ID {
	return b58.Decode(s)
}

// IDFromPubKey retrieves a Public Key from the peer given by pk
func IDFromPubKey(pk ic.PubKey) (ID, error) {
	b, err := pk.Bytes()
	if err != nil {
		return nil, err
	}
	hash := u.Hash(b)
	return ID(hash), nil
}

// Map maps Key (string) : *peer (slices are not comparable).
type Map map[u.Key]Peer

// Peer represents the identity information of an IPFS Node, including
// ID, and relevant Addresses.
type Peer interface {

	// TODO reduce the peer interface to be read-only. Force mutations to occur
	// on the peer store eg. peerstore.SetLatency(peerId, value).

	// ID returns the peer's ID
	ID() ID

	// Key returns the ID as a Key (string) for maps.
	Key() u.Key

	// Addresses returns the peer's multiaddrs
	Addresses() []ma.Multiaddr

	// AddAddress adds the given Multiaddr address to Peer's addresses.
	// returns whether this was a newly added address.
	AddAddress(a ma.Multiaddr) bool

	// NetAddress returns the first Multiaddr found for a given network.
	NetAddress(n string) ma.Multiaddr

	// Services returns the peer's services
	// Services() []mux.ProtocolID
	// SetServices([]mux.ProtocolID)

	// Priv/PubKey returns the peer's Private Key
	PrivKey() ic.PrivKey
	PubKey() ic.PubKey

	// LoadAndVerifyKeyPair unmarshalls, loads a private/public key pair.
	// Error if (a) unmarshalling fails, or (b) pubkey does not match id.
	LoadAndVerifyKeyPair(marshalled []byte) error
	VerifyAndSetPrivKey(sk ic.PrivKey) error
	VerifyAndSetPubKey(pk ic.PubKey) error

	// Get/SetLatency manipulate the current latency measurement.
	GetLatency() (out time.Duration)
	SetLatency(laten time.Duration)

	// Get/SetType indicate whether this is a local or remote peer
	GetType() Type
	SetType(Type)

	//Get/Set Agent and Protocol Versions
	GetVersions() (agent, protocol string)
	SetVersions(agent, protocol string)
	// Update with the data of another peer instance
	Update(Peer) error

	Loggable() map[string]interface{}
}

type Type uint8

const (
	// Unspecified indicates peer was created without specifying Type
	Unspecified Type = iota
	Local
	Remote
)

func (t Type) String() string {
	switch t {
	case Local:
		return "localPeer"
	case Remote:
		return "remotePeer"
	default:
	}
	return "unspecifiedPeer"
}

type peer struct {
	id        ID
	addresses []ma.Multiaddr
	// services  []mux.ProtocolID

	privKey ic.PrivKey
	pubKey  ic.PubKey

	// TODO move latency away from peer into the package that uses it. Instead,
	// within that package, map from ID to latency value.
	latency time.Duration

	protocolVersion string
	agentVersion    string

	// typ can be Local, Remote, or Unspecified (default)
	typ Type

	sync.RWMutex
}

// String prints out the peer.
//
// TODO(brian): ensure correctness at ID generation and
// enforce this by only exposing functions that generate
// IDs safely. Then any peer.ID type found in the
// codebase is known to be correct.
func (p *peer) String() string {
	pid := p.id.String()
	maxRunes := 12
	if len(pid) < maxRunes {
		maxRunes = len(pid)
	}
	return "[Peer " + pid[:maxRunes] + "]"
}

func (p *peer) Loggable() map[string]interface{} {
	return map[string]interface{}{
		p.GetType().String(): map[string]interface{}{
			"id":      p.ID(),
			"latency": p.GetLatency(),
		},
	}
}

// Key returns the ID as a Key (string) for maps.
func (p *peer) Key() u.Key {
	return u.Key(p.id)
}

// ID returns the peer's ID
func (p *peer) ID() ID {
	return p.id
}

// PrivKey returns the peer's Private Key
func (p *peer) PrivKey() ic.PrivKey {
	return p.privKey
}

// PubKey returns the peer's Private Key
func (p *peer) PubKey() ic.PubKey {
	return p.pubKey
}

// Addresses returns the peer's multiaddrs
func (p *peer) Addresses() []ma.Multiaddr {
	cp := make([]ma.Multiaddr, len(p.addresses))
	p.RLock()
	copy(cp, p.addresses)
	defer p.RUnlock()
	return cp
}

// AddAddress adds the given Multiaddr address to Peer's addresses.
// Returns whether this address was a newly added address
func (p *peer) AddAddress(a ma.Multiaddr) bool {
	p.Lock()
	defer p.Unlock()

	for _, addr := range p.addresses {
		if addr.Equal(a) {
			return false
		}
	}
	p.addresses = append(p.addresses, a)
	return true
}

// NetAddress returns the first Multiaddr found for a given network.
func (p *peer) NetAddress(n string) ma.Multiaddr {
	p.RLock()
	defer p.RUnlock()

	for _, a := range p.addresses {
		for _, p := range a.Protocols() {
			if p.Name == n {
				return a
			}
		}
	}
	return nil
}

// func (p *peer) Services() []mux.ProtocolID {
// 	p.RLock()
// 	defer p.RUnlock()
// 	return p.services
// }
//
// func (p *peer) SetServices(s []mux.ProtocolID) {
// 	p.Lock()
// 	defer p.Unlock()
// 	p.services = s
// }

// GetLatency retrieves the current latency measurement.
func (p *peer) GetLatency() (out time.Duration) {
	p.RLock()
	out = p.latency
	p.RUnlock()
	return
}

// SetLatency sets the latency measurement.
// TODO: Instead of just keeping a single number,
//		 keep a running average over the last hour or so
// Yep, should be EWMA or something. (-jbenet)
func (p *peer) SetLatency(laten time.Duration) {
	p.Lock()
	if p.latency == 0 {
		p.latency = laten
	} else {
		p.latency = ((p.latency * 9) + laten) / 10
	}
	p.Unlock()
}

func (p *peer) SetType(t Type) {
	p.Lock()
	p.typ = t
	defer p.Unlock()
}

func (p *peer) GetType() Type {
	p.Lock()
	defer p.Unlock()
	return p.typ
}

// LoadAndVerifyKeyPair unmarshalls, loads a private/public key pair.
// Error if (a) unmarshalling fails, or (b) pubkey does not match id.
func (p *peer) LoadAndVerifyKeyPair(marshalled []byte) error {
	sk, err := ic.UnmarshalPrivateKey(marshalled)
	if err != nil {
		return fmt.Errorf("Failed to unmarshal private key: %v", err)
	}

	return p.VerifyAndSetPrivKey(sk)
}

// VerifyAndSetPrivKey sets private key, given its pubkey matches the peer.ID
func (p *peer) VerifyAndSetPrivKey(sk ic.PrivKey) error {

	// construct and assign pubkey. ensure it matches this peer
	if err := p.VerifyAndSetPubKey(sk.GetPublic()); err != nil {
		return err
	}

	p.Lock()
	defer p.Unlock()

	// if we didn't have the priavte key, assign it
	if p.privKey == nil {
		p.privKey = sk
		return nil
	}

	// if we already had the keys, check they're equal.
	if p.privKey.Equals(sk) {
		return nil // as expected. keep the old objects.
	}

	// keys not equal. invariant violated. this warrants a panic.
	// these keys should be _the same_ because peer.ID = H(pk)
	// this mismatch should never happen.
	log.Errorf("%s had PrivKey: %v -- got %v", p, p.privKey, sk)
	panic("invariant violated: unexpected key mismatch")
}

// VerifyAndSetPubKey sets public key, given it matches the peer.ID
func (p *peer) VerifyAndSetPubKey(pk ic.PubKey) error {
	pkid, err := IDFromPubKey(pk)
	if err != nil {
		return fmt.Errorf("Failed to hash public key: %v", err)
	}

	p.Lock()
	defer p.Unlock()

	if !p.id.Equal(pkid) {
		return fmt.Errorf("Public key does not match peer.ID.")
	}

	// if we didn't have the keys, assign them.
	if p.pubKey == nil {
		p.pubKey = pk
		return nil
	}

	// if we already had the pubkey, check they're equal.
	if p.pubKey.Equals(pk) {
		return nil // as expected. keep the old objects.
	}

	// keys not equal. invariant violated. this warrants a panic.
	// these keys should be _the same_ because peer.ID = H(pk)
	// this mismatch should never happen.
	log.Errorf("%s had PubKey: %v -- got %v", p, p.pubKey, pk)
	panic("invariant violated: unexpected key mismatch")
}

// Updates this peer with information from another peer instance
func (p *peer) Update(other Peer) error {
	if !p.ID().Equal(other.ID()) {
		return errors.New("peer ids do not match")
	}

	for _, a := range other.Addresses() {
		p.AddAddress(a)
	}

	p.SetLatency(other.GetLatency())

	p.SetType(other.GetType())

	sk := other.PrivKey()
	pk := other.PubKey()
	p.Lock()
	if p.privKey == nil {
		p.privKey = sk
	}

	if p.pubKey == nil {
		p.pubKey = pk
	}
	defer p.Unlock()
	return nil
}

func (p *peer) GetVersions() (agent, protocol string) {
	p.RLock()
	defer p.RUnlock()
	return p.agentVersion, p.protocolVersion
}

func (p *peer) SetVersions(agent, protocol string) {
	p.Lock()
	defer p.Unlock()
	p.agentVersion = agent
	p.protocolVersion = protocol
}

// WithKeyPair returns a Peer object with given keys.
func WithKeyPair(sk ic.PrivKey, pk ic.PubKey) (Peer, error) {
	if sk == nil && pk == nil {
		return nil, fmt.Errorf("PeerWithKeyPair nil keys")
	}

	pk2 := sk.GetPublic()
	if pk == nil {
		pk = pk2
	} else if !pk.Equals(pk2) {
		return nil, fmt.Errorf("key mismatch. pubkey is not privkey's pubkey")
	}

	pkid, err := IDFromPubKey(pk)
	if err != nil {
		return nil, fmt.Errorf("Failed to hash public key: %v", err)
	}

	return &peer{id: pkid, pubKey: pk, privKey: sk}, nil
}

// WithID constructs a peer with given ID.
func WithID(id ID) Peer {
	return &peer{id: id}
}

// WithIDString constructs a peer with given ID (string).
func WithIDString(id string) Peer {
	return WithID(ID(id))
}
