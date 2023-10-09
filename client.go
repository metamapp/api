package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"mime/multipart"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/metamapp/api/jsoncdc"
	"github.com/metamapp/api/raw"
	"github.com/onflow/cadence"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/sha3"
)

var (
	errInvalidNonce = errors.New("api: invalid .Nonce value specified")
)

// ChallengeRequest defines the interface a client request struct needs to
// implement if it needs to be accompanied with a challenge and proof.
type ChallengeRequest interface {
	Difficulty(cfg Difficulty) int
	ToTxn() (*raw.Transaction, error)
}

// Client provides a Mappchain API client.
type Client struct {
	client      *http.Client
	debug       func(format string, args ...interface{})
	info        *GetChainInfoResponse
	infoMu      sync.RWMutex
	infoUpdated time.Time
	endpoint    string
	mu          sync.RWMutex
	signer      *Signer
}

// CreateAccount sends a request to create a new account.
func (c *Client) CreateAccount(ctx context.Context, key *SigningKey, req *CreateAccountRequest) (*CreateAccountResponse, error) {
	if req.Nonce == "" {
		nonce, err := genNonce()
		if err != nil {
			return nil, err
		}
		req.Nonce = nonce
	} else if !isValidNonce(req.Nonce) {
		return nil, errInvalidNonce
	}
	if req.PublicKey.Value == "" {
		if key == nil {
			return nil, fmt.Errorf(
				"api: `key` parameter cannot be nil for CreateAccount call with unspecified .PublicKey.Value",
			)
		}
		req.PublicKey = key.PublicKey()
	}
	if req.Challenge == "" && req.Proof == "" {
		challenge, proof, err := c.genProof(ctx, req, nil)
		if err != nil {
			return nil, err
		}
		req.Challenge = challenge
		req.Proof = proof
	}
	resp := &CreateAccountResponse{}
	err := c.do(ctx, "CreateAccount", req, resp)
	return resp, err
}

// ExecuteRead sends a request to execute a read transaction.
func (c *Client) ExecuteRead(ctx context.Context, req *ExecuteReadRequest) (*ExecuteReadResponse, error) {
	resp := &ExecuteReadResponse{}
	err := c.do(ctx, "ExecuteRead", req, resp)
	return resp, err
}

// ExecuteWrite sends a request to execute a write transaction.
func (c *Client) ExecuteWrite(ctx context.Context, req *ExecuteWriteRequest) (*ExecuteWriteResponse, error) {
	if req.Nonce == "" {
		nonce, err := genNonce()
		if err != nil {
			return nil, err
		}
		req.Nonce = nonce
	} else if !isValidNonce(req.Nonce) {
		return nil, errInvalidNonce
	}
	txn, err := req.ToTxn()
	if err != nil {
		return nil, fmt.Errorf("api: failed to convert transaction request: %s", err)
	}
	if len(req.Signatures) == 0 {
		c.mu.RLock()
		signer := c.signer
		c.mu.RUnlock()
		if signer == nil {
			return nil, fmt.Errorf(
				"api: missing .Signatures value in request and auto-signing is not enabled",
			)
		}
		hash, err := txn.PayloadHash()
		if err != nil {
			return nil, err
		}
		raw, err := c.signer.SigningKey.Sign(hash)
		if err != nil {
			return nil, err
		}
		sig := Signature{
			AccountID: signer.AccountID,
			KeyIndex:  signer.KeyIndex,
			Value:     hex.EncodeToString(raw),
		}
		tsig, err := sig.ToRaw()
		if err != nil {
			return nil, err
		}
		c.debug(
			"Generated transaction signature (%x) using key (%s)",
			raw, signer.SigningKey.publicKey,
		)
		req.Signatures = append(req.Signatures, sig)
		txn.Signatures = append(txn.Signatures, tsig)
	}
	if req.Challenge == "" && req.Proof == "" {
		challenge, proof, err := c.genProof(ctx, req, txn)
		if err != nil {
			return nil, err
		}
		req.Challenge = challenge
		req.Proof = proof
	}
	resp := &ExecuteWriteResponse{}
	err = c.do(ctx, "ExecuteWrite", req, resp)
	return resp, err
}

// GetBlock sends a request to get the info for a specific block.
func (c *Client) GetBlock(ctx context.Context, req *GetBlockRequest) (*GetBlockResponse, error) {
	resp := &GetBlockResponse{}
	err := c.do(ctx, "GetBlock", req, resp)
	return resp, err
}

// GetChainInfo sends a request to get the chain metadata.
func (c *Client) GetChainInfo(ctx context.Context) (*GetChainInfoResponse, error) {
	resp := &GetChainInfoResponse{}
	err := c.do(ctx, "GetChainInfo", map[string]string{}, resp)
	return resp, err
}

// GetTransactionResult sends a request to get the state of a transaction.
func (c *Client) GetTransactionResult(ctx context.Context, req *GetTransactionResultRequest) (*GetTransactionResultResponse, error) {
	resp := &GetTransactionResultResponse{}
	err := c.do(ctx, "GetTransactionResult", req, resp)
	return resp, err
}

// ListFieldValues sends a request to get all values of a specific event field.
func (c *Client) ListFieldValues(ctx context.Context, req *ListFieldValuesRequest) (*ListFieldValuesResponse, error) {
	resp := &ListFieldValuesResponse{}
	err := c.do(ctx, "ListFieldValues", req, resp)
	return resp, err
}

// QueryEvents sends a request to query blocks for a specific event type.
func (c *Client) QueryEvents(ctx context.Context, req *QueryEventsRequest) (*QueryEventsResponse, error) {
	resp := &QueryEventsResponse{}
	err := c.do(ctx, "QueryEvents", req, resp)
	return resp, err
}

// SetSigner enables auto-signing with the given account.
func (c *Client) SetSigner(s *Signer) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if s != nil {
		if s.AccountID == "" {
			return fmt.Errorf("api: missing AccountID for signer")
		}
		if s.SigningKey == nil {
			return fmt.Errorf("api: missing SigningKey value for signer")
		}
		if s.SigningKey.privateKey == nil {
			return fmt.Errorf("api: missing SigningKey.privateKey value for signer")
		}
	}
	c.signer = s
	return nil
}

// UploadFile sends a request to upload a file to the chain.
func (c *Client) UploadFile(ctx context.Context, req *UploadFileRequest) (*UploadFileResponse, error) {
	if req.Nonce == "" {
		nonce, err := genNonce()
		if err != nil {
			return nil, err
		}
		req.Nonce = nonce
	} else if !isValidNonce(req.Nonce) {
		return nil, errInvalidNonce
	}
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", "file")
	if err != nil {
		return nil, fmt.Errorf("api: failed to create multipart: %s", err)
	}
	_, err = part.Write(req.File)
	if err != nil {
		return nil, fmt.Errorf("api: failed to create multipart: %s", err)
	}
	if req.Challenge == "" && req.Proof == "" {
		challenge, proof, err := c.genProof(ctx, req, nil)
		if err != nil {
			return nil, err
		}
		req.Challenge = challenge
		req.Proof = proof
	}
	for _, param := range [][2]string{
		{"challenge", req.Challenge},
		{"nonce", req.Nonce},
		{"proof", req.Proof},
	} {
		err = writer.WriteField(param[0], param[1])
		if err != nil {
			return nil, fmt.Errorf("api: failed to create multipart: %s", err)
		}
	}
	err = writer.Close()
	if err != nil {
		return nil, fmt.Errorf("api: failed to create multipart: %s", err)
	}
	r, err := http.NewRequestWithContext(ctx, "POST", c.endpoint+"UploadFile", body)
	if err != nil {
		return nil, fmt.Errorf("api: failed to create request: %s", err)
	}
	r.Header.Set("Content-Type", writer.FormDataContentType())
	resp := &UploadFileResponse{}
	return resp, c.doReq(r, resp)
}

func (c *Client) do(ctx context.Context, method string, req interface{}, resp interface{}) error {
	enc, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("api: failed to encode request: %s", err)
	}
	r, err := http.NewRequestWithContext(ctx, "POST", c.endpoint+method, bytes.NewReader(enc))
	if err != nil {
		return fmt.Errorf("api: failed to create request: %s", err)
	}
	return c.doReq(r, resp)
}

func (c *Client) doReq(r *http.Request, v interface{}) error {
	resp, err := c.client.Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("api: failed to read response body: %s", err)
	}
	if resp.StatusCode != 200 {
		xerr := &ErrorResponse{}
		err := json.Unmarshal(out, xerr)
		if err != nil {
			return fmt.Errorf("api: failed to decode error response: %s", err)
		}
		return xerr.Error
	}
	err = json.Unmarshal(out, v)
	if err != nil {
		return fmt.Errorf("api: failed to decode response: %s: %q", err, out)
	}
	return nil
}

func (c *Client) genProof(ctx context.Context, req ChallengeRequest, txn *raw.Transaction) (string, string, error) {
	if txn == nil {
		var err error
		txn, err = req.ToTxn()
		if err != nil {
			return "", "", fmt.Errorf("api: failed to convert transaction request: %s", err)
		}
	}
	hash, err := txn.DeriveHash()
	if err != nil {
		return "", "", fmt.Errorf("api: failed to derive transaction hash: %s", err)
	}
	info, err := c.latestInfo(ctx)
	if err != nil {
		return "", "", fmt.Errorf("api: failed to get latest chain info: %s", err)
	}
	kdf := info.KDFParams
	if kdf.Algorithm != "argon2id" {
		return "", "", fmt.Errorf(
			"api: unknown challenge generation algorithm: %q", kdf.Algorithm,
		)
	}
	challenge, err := hex.DecodeString(info.Challenge)
	if err != nil {
		return "", "", fmt.Errorf("api: failed to decode challenge from chain info: %s", err)
	}
	difficulty := req.Difficulty(info.Difficulty)
	if difficulty > kdf.KeyLength {
		difficulty = kdf.KeyLength
	}
	buf := make([]byte, 48)
	copy(buf[16:], hash)
	idx := 0
pow:
	for {
		idx++
		_, err := rand.Read(buf[:16])
		if err != nil {
			return "", "", fmt.Errorf("api: failed to read random bytes for proof generation: %s", err)
		}
		key := argon2.IDKey(
			buf,
			challenge,
			uint32(kdf.Iterations),
			uint32(kdf.Memory),
			uint8(kdf.Parallelism),
			uint32(kdf.KeyLength),
		)
		found := 0
		for _, char := range key {
			count := bits.LeadingZeros8(char)
			found += count
			if found >= difficulty {
				c.log(
					"Generated challenge proof %x with result %x for transaction %x with difficulty %d at attempt %d",
					buf[:16], key, hash, difficulty, idx,
				)
				return info.Challenge, hex.EncodeToString(buf[:16]), nil
			}
			if count != 8 {
				continue pow
			}
		}
	}
}

func (c *Client) latestInfo(ctx context.Context) (*GetChainInfoResponse, error) {
	c.infoMu.RLock()
	if c.info == nil || time.Since(c.infoUpdated) > c.info.CheckInterval() {
		c.infoMu.RUnlock()
		info, err := c.GetChainInfo(ctx)
		if err != nil {
			return nil, err
		}
		now := time.Now()
		c.infoMu.Lock()
		c.info = info
		c.infoUpdated = now
		c.infoMu.Unlock()
		return info, nil
	}
	info := c.info
	c.infoMu.RUnlock()
	return info, nil
}

func (c *Client) log(format string, a ...interface{}) {
	if c.debug != nil {
		c.debug(format, a...)
	}
}

// ClientOption values can be used to configure the API client.
type ClientOption func(*Client)

// Signer represents an on-chain account and its signing key.
type Signer struct {
	AccountID  string
	KeyIndex   uint32
	SigningKey *SigningKey
}

// SigningKey represents a key to use for signing transactions.
type SigningKey struct {
	publicKey  string
	privateKey *secp256k1.PrivateKey
}

// PublicKey returns the default public key specification for the signing key.
func (s *SigningKey) PublicKey() PublicKey {
	return PublicKey{
		HashAlgorithm:    "SHA3_256",
		SigningAlgorithm: "ECDSA_secp256k1",
		Value:            s.publicKey,
		Weight:           1000,
	}
}

// RawPrivateKey returns the raw bytes of the underlying private key.
func (s *SigningKey) RawPrivateKey() []byte {
	return s.privateKey.Serialize()
}

// Sign will sign the given transaction hash with the underlying private key.
func (s *SigningKey) Sign(data []byte) ([]byte, error) {
	hasher := sha3.New256()
	tag := make([]byte, 32)
	copy(tag, "mappchain.transaction.v0")
	_, err := hasher.Write(tag)
	if err != nil {
		return nil, fmt.Errorf("api: failed to write to hasher: %s", err)
	}
	_, err = hasher.Write(data)
	if err != nil {
		return nil, fmt.Errorf("api: failed to write to hasher: %s", err)
	}
	hash := hasher.Sum(nil)
	sig := ecdsa.SignCompact(s.privateKey, hash, true)
	return sig, nil
}

// CadenceArgs serializes the given Cadence values.
func CadenceArgs(args ...cadence.Value) ([]json.RawMessage, error) {
	vals := make([]json.RawMessage, len(args))
	for i, arg := range args {
		enc, err := jsoncdc.Marshal(arg)
		if err != nil {
			return nil, fmt.Errorf(
				"api: failed to encode cadence value %s: %s", arg, err,
			)
		}
		vals[i] = enc
	}
	return vals, nil
}

// GenerateKey creates a fresh key for signing transactions.
func GenerateKey() (*SigningKey, error) {
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("api: failed to generate secp256k1 key: %s", err)
	}
	pub := priv.PubKey().SerializeCompressed()
	return &SigningKey{
		privateKey: priv,
		publicKey:  hex.EncodeToString(pub),
	}, nil
}

// JSONMessagesToByteSlices converts a slice of json RawMessage values to a
// slice of plain byte slices.
func JSONMessagesToByteSlices(args []json.RawMessage) [][]byte {
	xargs := make([][]byte, len(args))
	for i, arg := range args {
		xargs[i] = arg
	}
	return xargs
}

// MustCadenceArgs tries to serialize the given Cadence values and panics with
// an error if it fails.
func MustCadenceArgs(args ...cadence.Value) []json.RawMessage {
	vals, err := CadenceArgs(args...)
	if err != nil {
		panic(fmt.Errorf("api: failed to serialize cadence value: %s", err))
	}
	return vals
}

// NewClient returns a new Mappchain API client.
func NewClient(opts ...ClientOption) *Client {
	c := &Client{}
	for _, opt := range opts {
		opt(c)
	}
	if c.endpoint == "" {
		c.endpoint = "https://chain.metamapp.xyz"
	}
	if c.client == nil {
		c.client = &http.Client{
			Timeout: 30 * time.Second,
		}
	}
	return c
}

// WithEndpoint configures the API client with a specific API endpoint.
func WithEndpoint(v string) ClientOption {
	v = strings.TrimSuffix(v, "/")
	v = strings.TrimSuffix(v, "/api/v1")
	return func(c *Client) {
		c.endpoint = v + "/api/v1/"
	}
}

// WithDebugLogger configures the API client with a specific debug logger.
func WithDebugLogger(log func(format string, args ...interface{})) ClientOption {
	return func(c *Client) {
		c.debug = log
	}
}

// WithTimeout configures the API client with a specific timeout duration.
func WithTimeout(d time.Duration) ClientOption {
	return func(c *Client) {
		c.client = &http.Client{
			Timeout: d,
		}
	}
}

func asBytesSlice(args []json.RawMessage) [][]byte {
	xargs := make([][]byte, len(args))
	for i, arg := range args {
		xargs[i] = arg
	}
	return xargs
}

func cadenceArgsBytes(args ...cadence.Value) ([][]byte, error) {
	vals := make([][]byte, len(args))
	for i, arg := range args {
		enc, err := jsoncdc.Marshal(arg)
		if err != nil {
			return nil, fmt.Errorf(
				"api: failed to encode cadence value %s: %s", arg, err,
			)
		}
		vals[i] = enc
	}
	return vals, nil
}

func genNonce() (string, error) {
	buf := make([]byte, 16)
	_, err := rand.Read(buf)
	if err != nil {
		return "", fmt.Errorf("api: failed to generate random nonce: %s", err)
	}
	return hex.EncodeToString(buf), nil
}

func isValidNonce(nonce string) bool {
	if len(nonce) != 32 {
		return false
	}
	_, err := hex.DecodeString(nonce)
	return err == nil
}
