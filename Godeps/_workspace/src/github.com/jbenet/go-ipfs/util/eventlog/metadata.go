package eventlog

import (
	"encoding/json"
	"errors"
	"reflect"

	"github.com/maybebtc/keygen/Godeps/_workspace/src/code.google.com/p/go-uuid/uuid"
)

// Metadata is a convenience type for generic maps
type Metadata map[string]interface{}

// Loggable describes objects that can be marshalled into Metadata for logging
type Loggable interface {
	Loggable() map[string]interface{}
}

// Uuid returns a Metadata with the string key and UUID value
func Uuid(key string) Metadata {
	return Metadata{
		key: uuid.New(),
	}
}

// DeepMerge merges the second Metadata parameter into the first.
// Nested Metadata are merged recursively. Primitives are over-written.
func DeepMerge(b, a Metadata) Metadata {
	out := Metadata{}
	for k, v := range b {
		out[k] = v
	}
	for k, v := range a {

		maybe, err := Metadatify(v)
		if err != nil {
			// if the new value is not meta. just overwrite the dest vaue
			out[k] = v
			continue
		}

		// it is meta. What about dest?
		outv, exists := out[k]
		if !exists {
			// the new value is meta, but there's no dest value. just write it
			out[k] = v
			continue
		}

		outMetadataValue, err := Metadatify(outv)
		if err != nil {
			// the new value is meta and there's a dest value, but the dest
			// value isn't meta. just overwrite
			out[k] = v
			continue
		}

		// both are meta. merge them.
		out[k] = DeepMerge(outMetadataValue, maybe)
	}
	return out
}

// Loggable implements the Loggable interface
func (m Metadata) Loggable() map[string]interface{} {
	// NB: method defined on value to avoid de-referencing nil Metadata
	return m
}

func (m Metadata) JsonString() (string, error) {
	// NB: method defined on value
	b, err := json.Marshal(m)
	return string(b), err
}

// Metadatify converts maps into Metadata
func Metadatify(i interface{}) (Metadata, error) {
	value := reflect.ValueOf(i)
	if value.Kind() == reflect.Map {
		m := map[string]interface{}{}
		for _, k := range value.MapKeys() {
			m[k.String()] = value.MapIndex(k).Interface()
		}
		return Metadata(m), nil
	}
	return nil, errors.New("is not a map")
}
