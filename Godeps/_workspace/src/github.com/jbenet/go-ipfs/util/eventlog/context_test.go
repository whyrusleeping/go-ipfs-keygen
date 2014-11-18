package eventlog

import (
	"testing"

	"github.com/maybebtc/keygen/Godeps/_workspace/src/code.google.com/p/go.net/context"
)

func TestContextContainsMetadata(t *testing.T) {
	t.Parallel()

	m := Metadata{"foo": "bar"}
	ctx := ContextWithMetadata(context.Background(), m)
	got, err := MetadataFromContext(ctx)
	if err != nil {
		t.Fatal(err)
	}

	_, exists := got["foo"]
	if !exists {
		t.Fail()
	}
}

func TestContextWithPreexistingMetadata(t *testing.T) {
	t.Parallel()

	ctx := ContextWithMetadata(context.Background(), Metadata{"hello": "world"})
	ctx = ContextWithMetadata(ctx, Metadata{"goodbye": "earth"})

	got, err := MetadataFromContext(ctx)
	if err != nil {
		t.Fatal(err)
	}

	_, exists := got["hello"]
	if !exists {
		t.Fatal("original key not present")
	}
	_, exists = got["goodbye"]
	if !exists {
		t.Fatal("new key not present")
	}
}
