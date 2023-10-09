package raw

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"

	"lukechampine.com/blake3"
)

// Hard limits.
const (
	MaxEncodedArgumentLength = 1 << 18 // Could be increased up to maxUint24
	MaxNumberOfArguments     = math.MaxUint8
	MaxScriptLength          = 1 << 18 // Could be increased up to maxUint24
	MaxSignatures            = math.MaxUint8
	MaxSignatureLength       = math.MaxUint16
	NonceLength              = 16
)

// DeriveHash computes the transaction hash.
func (t *Transaction) DeriveHash() ([]byte, error) {
	buf := make([]byte, 8)
	out := &bytes.Buffer{}
	hash, err := t.payloadHash(buf, out)
	if err != nil {
		return nil, err
	}
	out.Reset()
	out.Write(hash)
	txnHash, err := t.transactionHash(buf, out)
	return txnHash, err
}

// PayloadHash computes the payload hash.
func (t *Transaction) PayloadHash() ([]byte, error) {
	buf := make([]byte, 8)
	out := &bytes.Buffer{}
	return t.payloadHash(buf, out)
}

// UpdateHash computes and sets the transaction hash.
func (t *Transaction) UpdateHash() error {
	hash, err := t.DeriveHash()
	if err != nil {
		return err
	}
	t.Hash = hash
	return nil
}

func (t *Transaction) payloadHash(buf []byte, out *bytes.Buffer) ([]byte, error) {
	if t.Type > math.MaxUint8 {
		return nil, fmt.Errorf(
			"model: transaction type value %d exceeds max limit: %d",
			t.Type, math.MaxUint8,
		)
	}
	out.WriteByte(byte(t.Type))
	if len(t.Arguments) > MaxNumberOfArguments {
		return nil, fmt.Errorf(
			"model: number of arguments (%d) in transaction exceeds max limit: %d",
			len(t.Arguments), MaxNumberOfArguments,
		)
	}
	out.WriteByte(byte(len(t.Arguments)))
	for i, arg := range t.Arguments {
		if len(arg) > MaxEncodedArgumentLength {
			return nil, fmt.Errorf(
				"model: length of arg %d (%d) in transaction exceeds max limit: %d",
				i, len(arg), MaxEncodedArgumentLength,
			)
		}
		binary.BigEndian.PutUint32(buf, uint32(len(arg)))
		out.Write(buf[:4])
		out.Write(arg)
	}
	if len(t.Script) > MaxScriptLength {
		return nil, fmt.Errorf(
			"model: length of the script (%d) for transaction exceeds max limit: %d",
			len(t.Script), MaxScriptLength,
		)
	}
	binary.BigEndian.PutUint32(buf, uint32(len(t.Script)))
	out.Write(buf[:4])
	out.WriteString(t.Script)
	if len(t.Nonce) != NonceLength {
		return nil, fmt.Errorf(
			"model: invalid length of nonce for transaction: expected %d, got %d",
			NonceLength, len(t.Nonce),
		)
	}
	out.Write(t.Nonce)
	hash := blake3.Sum256(out.Bytes())
	return hash[:], nil
}

func (t *Transaction) transactionHash(buf []byte, out *bytes.Buffer) ([]byte, error) {
	if len(t.Signatures) > MaxSignatures {
		return nil, fmt.Errorf(
			"model: number of signatures (%d) for transaction exceeds max limit: %d",
			len(t.Signatures), MaxSignatures,
		)
	}
	out.WriteByte(byte(len(t.Signatures)))
	for i, sig := range t.Signatures {
		if len(sig.Account) != 8 {
			return nil, fmt.Errorf(
				"model: invalid byte length of raw account for transaction signature: expected 8, got %d",
				len(sig.Account),
			)
		}
		if len(sig.Value) > MaxSignatureLength {
			return nil, fmt.Errorf(
				"model: length of signature %d (%d) in transaction exceeds max limit: %d",
				i, len(sig.Value), MaxSignatureLength,
			)
		}
		out.Write(sig.Account)
		binary.BigEndian.PutUint32(buf, sig.KeyIndex)
		out.Write(buf[:4])
		binary.BigEndian.PutUint16(buf, uint16(len(sig.Value)))
		out.Write(buf[:2])
		out.Write([]byte(sig.Value))
	}
	hash := blake3.Sum256(out.Bytes())
	return hash[:], nil
}
