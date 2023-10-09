// Package jsoncdc provides support for JSON encoding and decoding of Cadence
// values.
package jsoncdc

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/onflow/cadence"
	jsoncdc "github.com/onflow/cadence/encoding/json"
)

// Marshal encodes the cadence value into a canonicalized JSON form.
func Marshal(v cadence.Value) ([]byte, error) {
	out, err := jsoncdc.Encode(v)
	if err != nil {
		return nil, fmt.Errorf(
			"jsoncdc: failed to encode cadence value into JSON: %s", err,
		)
	}
	tmp := map[string]interface{}{}
	err = json.Unmarshal(out, &tmp)
	if err != nil {
		return nil, fmt.Errorf(
			"jsoncdc: failed to decode into a temporary map: %s", err,
		)
	}
	out, err = json.Marshal(tmp)
	if err != nil {
		return nil, fmt.Errorf(
			"jsoncdc: failed to re-encode cadence value into JSON: %s", err,
		)
	}
	return bytes.TrimSpace(out), nil
}

// Unmarshal decodes the given data into a cadence value.
func Unmarshal(data []byte, options ...jsoncdc.Option) (cadence.Value, error) {
	v, err := jsoncdc.Decode(nil, data, options...)
	if err != nil {
		return nil, fmt.Errorf(
			"jsoncdc: failed to decode JSON into a cadence value: %s", err,
		)
	}
	return v, nil
}
