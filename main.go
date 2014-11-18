package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/maybebtc/keygen/Godeps/_workspace/src/code.google.com/p/go.net/context"

	config "github.com/maybebtc/keygen/Godeps/_workspace/src/github.com/jbenet/go-ipfs/config"
	ci "github.com/maybebtc/keygen/Godeps/_workspace/src/github.com/jbenet/go-ipfs/crypto"
	peer "github.com/maybebtc/keygen/Godeps/_workspace/src/github.com/jbenet/go-ipfs/peer"
	"github.com/maybebtc/keygen/Godeps/_workspace/src/github.com/jbenet/go-ipfs/util/debugerror"
	"github.com/maybebtc/keygen/Godeps/_workspace/src/github.com/rcrowley/go-metrics"
)

var nBits = 1024
var numWorkers = runtime.NumCPU()

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	foo()
}

func try(ctx context.Context, g, s metrics.Meter, r *regexp.Regexp, n int, successes chan<- config.Identity) {
	for i := 0; i < n; i++ {
		go func() {
			for {
				conf, err := IdentityConfig(nBits)
				if err != nil {
					continue
				}
				g.Mark(1)
				if r.MatchString(conf.PeerID) {
					s.Mark(1)
					successes <- conf
				}

				select {
				case <-ctx.Done():
					return
				default:
				}
			}
		}()
	}
}

func foo() error {
	ctx, cancel := context.WithCancel(context.Background())

	var patterns []string
	for _, name := range desiredNames {
		patterns = append(patterns, genRegexpPattern(name))
	}
	r, err := genMetaPattern(patterns)
	if err != nil {
		return err
	}

	metricGen := metrics.NewMeter()
	metricSuc := metrics.NewMeter()

	successes := make(chan config.Identity)
	go try(ctx, metricGen, metricSuc, r, numWorkers, successes)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	lastInterrupt := time.Now()
	for {
		select {
		case <-c:
			if time.Since(lastInterrupt) < 1*time.Second {
				cancel()
				return nil
			}
			lastInterrupt = time.Now()

			fmt.Println("")
			fmt.Printf("%f keys/s <-> %f keys/hr | %f successes/hr | %f keys/success \n",
				metricGen.Rate15(),
				metricGen.Rate15()*60*60,
				metricSuc.Rate15()*60*60,
				metricGen.Rate15()/metricSuc.Rate15())
		case conf := <-successes:
			if err := saveIdentity(conf); err != nil {
				return err
			}
			fmt.Printf("saved %s\n", conf.PeerID)
		}
	}
	return nil
}

func saveIdentity(conf config.Identity) error {
	f, err := os.Create(conf.PeerID)
	if err != nil {
		return err
	}
	e := json.NewEncoder(f)
	e.Encode(conf)
	return f.Close()
}

// IdentityConfig initializes a new identity.
func IdentityConfig(nbits int) (config.Identity, error) {
	// TODO guard higher up
	ident := config.Identity{}
	if nbits < 1024 {
		return ident, debugerror.New("Bitsize less than 1024 is considered unsafe.")
	}

	sk, pk, err := ci.GenerateKeyPair(ci.RSA, nbits)
	if err != nil {
		return ident, err
	}

	// currently storing key unencrypted. in the future we need to encrypt it.
	// TODO(security)
	skbytes, err := sk.Bytes()
	if err != nil {
		return ident, err
	}
	ident.PrivKey = base64.StdEncoding.EncodeToString(skbytes)

	id, err := peer.IDFromPubKey(pk)
	if err != nil {
		return ident, err
	}
	ident.PeerID = id.Pretty()
	return ident, nil
}

func genMetaPattern(patterns []string) (*regexp.Regexp, error) {
	metaPattern := ""
	for _, pattern := range patterns {
		metaPattern += fmt.Sprintf("(%s)|", pattern)
	}
	metaPattern = metaPattern[:len(metaPattern)-1]
	return regexp.Compile(metaPattern)
}

func genRegexpPattern(name string) string {
	s := "^Qm"
	for _, r := range name {
		c := RuneToAscii(r)
		s += fmt.Sprintf("(%s|%s)", strings.ToLower(c), strings.ToUpper(c))
	}
	s += ".*"
	return s
}

func RuneToAscii(r rune) string {
	if r < 128 {
		return string(r)
	} else {
		panic("argh")
	}
}

var desiredNames = []string{
	"aaa",
	"ars",
	"brian",
	"btc",
	"chas",
	"danmane",
	"earth",
	"ercury",
	"foo",
	"ip",
	"ipn",
	"jbenet",
	"jiro",
	"juan",
	"jupiter",
	"mappum",
	"mars",
	"marsipn",
	"matt",
	"mercury",
	"nala",
	"neptune",
	"p2p",
	"pluto",
	"polarbear",
	"saturn",
	"sol",
	"terra",
	"uranus",
	"venus",
	"why",
	"xxx",
	"zzz",
}
