package spipe

import (
	"errors"

	context "github.com/maybebtc/keygen/Godeps/_workspace/src/code.google.com/p/go.net/context"
	peer "github.com/maybebtc/keygen/Godeps/_workspace/src/github.com/jbenet/go-ipfs/peer"

	pipes "github.com/maybebtc/keygen/Godeps/_workspace/src/github.com/jbenet/go-ipfs/util/pipes"
)

// SecurePipe objects represent a bi-directional message channel.
type SecurePipe struct {
	pipes.Duplex
	insecure pipes.Duplex

	local  peer.Peer
	remote peer.Peer
	peers  peer.Peerstore

	params params

	ctx    context.Context
	cancel context.CancelFunc
}

// options in a secure pipe
type params struct {
}

// NewSecurePipe constructs a pipe with channels of a given buffer size.
func NewSecurePipe(ctx context.Context, bufsize int, local peer.Peer,
	peers peer.Peerstore, insecure pipes.Duplex) (*SecurePipe, error) {

	ctx, cancel := context.WithCancel(ctx)

	sp := &SecurePipe{
		Duplex: pipes.Duplex{
			In:  make(chan []byte, bufsize),
			Out: make(chan []byte, bufsize),
		},
		local:    local,
		peers:    peers,
		insecure: insecure,

		ctx:    ctx,
		cancel: cancel,
	}

	if err := sp.handshake(); err != nil {
		sp.Close()
		return nil, err
	}

	return sp, nil
}

// LocalPeer retrieves the local peer.
func (s *SecurePipe) LocalPeer() peer.Peer {
	return s.local
}

// RemotePeer retrieves the local peer.
func (s *SecurePipe) RemotePeer() peer.Peer {
	return s.remote
}

// Close closes the secure pipe
func (s *SecurePipe) Close() error {
	select {
	case <-s.ctx.Done():
		return errors.New("already closed")
	default:
	}

	s.cancel()
	return nil
}
