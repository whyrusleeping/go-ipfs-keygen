package spipe

import (
	"testing"

	"github.com/maybebtc/keygen/Godeps/_workspace/src/code.google.com/p/go.net/context"

	ci "github.com/maybebtc/keygen/Godeps/_workspace/src/github.com/jbenet/go-ipfs/crypto"
	"github.com/maybebtc/keygen/Godeps/_workspace/src/github.com/jbenet/go-ipfs/peer"
	"github.com/maybebtc/keygen/Godeps/_workspace/src/github.com/jbenet/go-ipfs/util"
	"github.com/maybebtc/keygen/Godeps/_workspace/src/github.com/jbenet/go-ipfs/util/pipes"
)

func getPeer(tb testing.TB) peer.Peer {
	privk, pubk, err := ci.GenerateKeyPair(ci.RSA, 1024)
	if err != nil {
		tb.Fatal(err)
	}

	p, err := peer.WithKeyPair(privk, pubk)
	if err != nil {
		tb.Fatal(err)
	}

	return p
}

func bindDuplexNoCopy(a, b pipes.Duplex) {
	go func() {
		for m := range b.Out {
			a.In <- m
		}
	}()
	for m := range a.Out {
		b.In <- m
	}
}

var globuf = make([]byte, 4*1024*1024)

func bindDuplexWithCopy(a, b pipes.Duplex) {
	dup := func(byt []byte) []byte {
		n := globuf[:len(byt)]
		copy(n, byt)
		return n
	}
	go func() {
		for m := range b.Out {
			a.In <- dup(m)
		}
	}()
	for m := range a.Out {
		b.In <- dup(m)
	}
}

func BenchmarkDataEncryptDefault(b *testing.B) {
	SupportedExchanges = "P-256,P-224,P-384,P-521"
	SupportedCiphers = "AES-256,AES-128"
	SupportedHashes = "SHA256,SHA512,SHA1"

	runEncryptBenchmark(b)
}

func BenchmarkDataEncryptLite(b *testing.B) {
	SupportedExchanges = "P-256"
	SupportedCiphers = "AES-128"
	SupportedHashes = "SHA1"

	runEncryptBenchmark(b)
}

func BenchmarkDataEncryptBlowfish(b *testing.B) {
	SupportedExchanges = "P-256"
	SupportedCiphers = "Blowfish"
	SupportedHashes = "SHA1"

	runEncryptBenchmark(b)
}

func runEncryptBenchmark(b *testing.B) {
	pstore := peer.NewPeerstore()
	ctx := context.TODO()
	bufsize := 1024 * 1024

	pa := getPeer(b)
	pb := getPeer(b)
	duplexa := pipes.NewDuplex(16)
	duplexb := pipes.NewDuplex(16)

	go bindDuplexNoCopy(duplexa, duplexb)

	var spb *SecurePipe
	done := make(chan struct{})
	go func() {
		var err error
		spb, err = NewSecurePipe(ctx, bufsize, pb, pstore, duplexb)
		if err != nil {
			b.Fatal(err)
		}
		done <- struct{}{}
	}()

	spa, err := NewSecurePipe(ctx, bufsize, pa, pstore, duplexa)
	if err != nil {
		b.Fatal(err)
	}

	<-done

	go func() {
		for _ = range spa.In {
			// Throw it all away,
			// all of your hopes and dreams
			// piped out to /dev/null...
			done <- struct{}{}
		}
	}()

	data := make([]byte, 1024*512)
	util.NewTimeSeededRand().Read(data)
	// Begin actual benchmarking
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		b.SetBytes(int64(len(data)))
		spb.Out <- data
		<-done
	}

}

func BenchmarkDataTransfer(b *testing.B) {
	duplexa := pipes.NewDuplex(16)
	duplexb := pipes.NewDuplex(16)

	go bindDuplexWithCopy(duplexa, duplexb)

	done := make(chan struct{})
	go func() {
		for _ = range duplexa.In {
			// Throw it all away,
			// all of your hopes and dreams
			// piped out to /dev/null...
			done <- struct{}{}
		}
	}()

	data := make([]byte, 1024*512)
	util.NewTimeSeededRand().Read(data)
	// Begin actual benchmarking
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		b.SetBytes(int64(len(data)))
		duplexb.Out <- data
		<-done
	}

}
