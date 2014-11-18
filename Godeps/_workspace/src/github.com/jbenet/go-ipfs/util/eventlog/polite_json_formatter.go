package eventlog

import (
	"encoding/json"
	"fmt"

	"github.com/maybebtc/logrus"
)

// PoliteJSONFormatter marshals entries into JSON encoded slices (without
// overwriting user-provided keys). How polite of it!
type PoliteJSONFormatter struct{}

func (f *PoliteJSONFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	serialized, err := json.Marshal(entry.Data)
	if err != nil {
		return nil, fmt.Errorf("Failed to marshal fields to JSON, %v", err)
	}
	return append(serialized, '\n'), nil
}
