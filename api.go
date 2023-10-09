// Package api implements the Mappchain API.
package api

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/metamapp/api/jsoncdc"
	"github.com/metamapp/api/raw"
	"github.com/onflow/cadence"
	"lukechampine.com/blake3"
)

// CreateAccountRequest represents the /api/v1/CreateAccount request.
type CreateAccountRequest struct {
	About     string    `json:"about"`
	Challenge string    `json:"challenge"`
	Image     string    `json:"image"`
	Name      string    `json:"name"`
	Nonce     string    `json:"nonce"`
	Proof     string    `json:"proof"`
	PublicKey PublicKey `json:"publicKey"`
	Tags      []string  `json:"tags"`
}

func (c *CreateAccountRequest) Difficulty(cfg Difficulty) int {
	return int(math.Ceil(cfg.CreateAccount))
}

func (c *CreateAccountRequest) ToTxn() (*raw.Transaction, error) {
	nonce, err := hex.DecodeString(c.Nonce)
	if err != nil {
		return nil, err
	}
	tags := make([]cadence.Value, len(c.Tags))
	for i, tag := range c.Tags {
		tags[i] = cadence.String(tag)
	}
	args, err := cadenceArgsBytes(
		cadence.String(c.PublicKey.Value),
		cadence.String(c.About),
		cadence.String(c.Name),
		cadence.String(c.Image),
		cadence.NewArray(tags),
	)
	// log.Errorf("ARGS: %s", args)
	if err != nil {
		return nil, err
	}
	return &raw.Transaction{
		Arguments: args,
		Nonce:     nonce,
		Type:      raw.TransactionType_CREATE_ACCOUNT,
	}, nil
}

// CreateAccountResponse represents the /api/v1/CreateAccount response.
type CreateAccountResponse struct {
	TransactionHash string `json:"transactionHash"`
}

// Difficulty specifies the difficulty level for different operations.
type Difficulty struct {
	CreateAccount float64 `json:"createAccount"`
	ExecuteWrite  float64 `json:"executeWrite"`
	PerKilobyte   float64 `json:"perKilobyte"`
	UploadFile    float64 `json:"uploadFile"`
}

// ErrorInfo specifies details about a site error.
type ErrorInfo struct {
	Message string `json:"message"`
	Type    string `json:"type"`
}

func (e ErrorInfo) Error() string {
	return fmt.Sprintf(
		"api: got a metamapp client error of type %q: %s",
		e.Type, e.Message,
	)
}

// ErrorResponse represents a site error response.
type ErrorResponse struct {
	Error ErrorInfo `json:"error"`
}

// Event represents an individual event emitted during transaction execution.
type Event struct {
	Fields []*Field `json:"fields"`
	Type   string   `json:"type"`
}

// EventOccurence represents the individual occurence of an event within a
// transaction.
type EventOccurence struct {
	BlockHeight      uint64 `json:"blockHeight"`
	Event            Event  `json:"event"`
	EventIndex       uint32 `json:"eventIndex"`
	TransactionHash  string `json:"transactionHash"`
	TransactionIndex uint32 `json:"transactionIndex"`
}

// ExecuteReadRequest represents the /api/v1/ExecuteRead request.
type ExecuteReadRequest struct {
	Arguments []json.RawMessage `json:"args"`
	Height    uint64            `json:"height"`
	Script    string            `json:"script"`
}

// ExecuteReadResponse represents the /api/v1/ExecuteRead response.
type ExecuteReadResponse struct {
	Result json.RawMessage `json:"result"`
}

// ExecuteWriteRequest represents the /api/v1/ExecuteWrite request.
type ExecuteWriteRequest struct {
	Arguments  []json.RawMessage `json:"args"`
	Challenge  string            `json:"challenge"`
	Nonce      string            `json:"nonce"`
	Proof      string            `json:"proof"`
	Script     string            `json:"script"`
	Signatures []Signature       `json:"signatures"`
}

func (e *ExecuteWriteRequest) Difficulty(cfg Difficulty) int {
	d := float64(len(e.Script)) / 1024
	d = d * cfg.PerKilobyte
	return int(math.Ceil(cfg.ExecuteWrite + d))
}

func (e *ExecuteWriteRequest) ToTxn() (*raw.Transaction, error) {
	nonce, err := hex.DecodeString(e.Nonce)
	if err != nil {
		return nil, err
	}
	sigs := make([]*raw.Signature, len(e.Signatures))
	for i, sig := range e.Signatures {
		raw, err := sig.ToRaw()
		if err != nil {
			return nil, err
		}
		sigs[i] = raw
	}
	return &raw.Transaction{
		Arguments:  asBytesSlice(e.Arguments),
		Nonce:      nonce,
		Script:     e.Script,
		Signatures: sigs,
		Type:       raw.TransactionType_EXECUTE_CADENCE,
	}, nil
}

// ExecuteWriteResponse represents the /api/v1/ExecuteWrite response.
type ExecuteWriteResponse struct {
	TransactionHash string `json:"transactionHash"`
}

// Field represents an individual field within an emitted event.
type Field struct {
	Name  string          `json:"name"`
	Value json.RawMessage `json:"value"`
}

// Filter defines a sub-query on the value of an event field.
type Filter struct {
	FieldIndex uint8           `json:"fieldIndex"`
	Operation  string          `json:"operation"`
	Value      json.RawMessage `json:"value"`
}

// GetBlockRequest represents the /api/v1/GetBlock request.
type GetBlockRequest struct {
	Height uint64 `json:"height"`
}

// GetBlockResponse represents the /api/v1/GetBlock response.
type GetBlockResponse struct {
	Executed      bool          `json:"executed"`
	Hash          string        `json:"hash"`
	Height        uint64        `json:"height"`
	PrevBlockHash string        `json:"prevBlockHash"`
	Timestamp     uint64        `json:"timestamp"`
	Transactions  []Transaction `json:"transactions"`
}

// GetChainInfoResponse represents the /api/v1/GetChainInfo response.
type GetChainInfoResponse struct {
	ChainID           uint64      `json:"chainId"`
	Challenge         string      `json:"challenge"`
	ChallengeRotation uint32      `json:"challengeRotation"`
	Difficulty        Difficulty  `json:"difficulty"`
	KDFParams         KDFParams   `json:"kdfParams"`
	LatestBlock       LatestBlock `json:"latestBlock"`
	MaxUploadFileSize int64       `json:"maxUploadFileSize"`
}

// CheckInterval returns the time duration for updating the challenge.
func (g *GetChainInfoResponse) CheckInterval() time.Duration {
	return time.Duration(g.ChallengeRotation) * (time.Second / 2)
}

// GetTransactionResultRequest represents the /api/v1/GetTransactionResult
// request.
type GetTransactionResultRequest struct {
	TransactionHash string `json:"transactionHash"`
}

// GetTransactionResultResponse represents the /api/v1/GetTransactionResult
// response.
type GetTransactionResultResponse struct {
	Executed bool               `json:"executed"`
	Height   uint64             `json:"height"`
	Result   *TransactionResult `json:"result"`
}

// KDFParams defines the configuration for applying the key derivation function.
type KDFParams struct {
	Algorithm   string `json:"algorithm"`
	Iterations  int    `json:"iterations"`
	KeyLength   int    `json:"keyLength"`
	Memory      int    `json:"memory"`
	Parallelism int    `json:"parallelism"`
}

// LatestBlock specifies the state of the latest blocks that have been produced
// and executed.
type LatestBlock struct {
	Executed uint64 `json:"executed"`
	Hash     string `json:"hash"`
	Height   uint64 `json:"height"`
}

// ListFieldValuesRequest represents the /api/v1/ListFieldValues request.
type ListFieldValuesRequest struct {
	Cursor     string `json:"cursor"`
	EventType  string `json:"eventType"`
	FieldIndex uint8  `json:"fieldIndex"`
}

// ListFieldValuesResponse represents the /api/v1/ListFieldValues request.
type ListFieldValuesResponse struct {
	Cursor string            `json:"cursor"`
	Values []json.RawMessage `json:"values"`
}

// PublicKey represents a public key for an account.
type PublicKey struct {
	HashAlgorithm    string `json:"hashAlgorithm"`
	SigningAlgorithm string `json:"signingAlgorithm"`
	Value            string `json:"value"`
	Weight           uint32 `json:"weight"`
}

// QueryEventsRequest represents the /api/v1/QueryEvents request.
type QueryEventsRequest struct {
	StartBlock uint64   `json:"startBlock"`
	EventType  string   `json:"eventType"`
	Filters    []Filter `json:"filters"`
}

// QueryEventsResponse represents the /api/v1/QueryEvents response.
type QueryEventsResponse struct {
	EndBlock uint64            `json:"endBlock"`
	Results  []*EventOccurence `json:"results"`
}

// Seal represents the hash for the events generated from a specific block.
type Seal struct {
	Hash   string `json:"hash"`
	Height uint64 `json:"height"`
}

// Signature represents the signature for an on-chain transaction.
type Signature struct {
	AccountID string `json:"accountId"`
	KeyIndex  uint32 `json:"keyIndex"`
	Value     string `json:"value"`
}

func (s Signature) ToRaw() (*raw.Signature, error) {
	if len(s.AccountID) < 2 || strings.ToLower(s.AccountID[:2]) != "0x" {
		return nil, fmt.Errorf("api: invalid account ID: %q", s.AccountID)
	}
	acctID, err := strconv.ParseUint(s.AccountID[2:], 16, 64)
	if err != nil {
		return nil, fmt.Errorf("api: failed to decode account ID: %s", err)
	}
	acct := make([]byte, 8)
	binary.BigEndian.PutUint64(acct, acctID)
	val, err := hex.DecodeString(s.Value)
	if err != nil {
		return nil, fmt.Errorf("api: failed to decode signature value: %s", err)
	}
	return &raw.Signature{
		Account:  acct,
		KeyIndex: s.KeyIndex,
		Value:    val,
	}, nil
}

// Transaction represents a transaction that has been processed on-chain.
type Transaction struct {
	Arguments  []json.RawMessage `json:"args"`
	Hash       string            `json:"hash"`
	Nonce      string            `json:"nonce"`
	Script     string            `json:"script"`
	Signatures []Signature       `json:"signatures"`
	Type       string            `json:"type"`
}

// TransactionResult represents the result of executing a transaction.
type TransactionResult struct {
	Error            string   `json:"error"`
	Events           []*Event `json:"events"`
	Log              []string `json:"log"`
	Status           string   `json:"status"`
	TransactionIndex uint32   `json:"transactionIndex"`
}

// UploadFileRequest represents the /api/v1/UploadFile request.
type UploadFileRequest struct {
	Challenge string `json:"challenge"`
	File      []byte `json:"file"`
	Nonce     string `json:"nonce"`
	Proof     string `json:"proof"`
}

func (u *UploadFileRequest) Difficulty(cfg Difficulty) int {
	d := float64(len(u.File)) / 1024
	d = d * cfg.PerKilobyte
	return int(math.Ceil(cfg.UploadFile + d))
}

func (u *UploadFileRequest) ToTxn() (*raw.Transaction, error) {
	nonce, err := hex.DecodeString(u.Nonce)
	if err != nil {
		return nil, err
	}
	hash := blake3.Sum256(u.File)
	fileHash := hex.EncodeToString(hash[:])
	arg, err := jsoncdc.Marshal(cadence.String(fileHash))
	if err != nil {
		return nil, err
	}
	return &raw.Transaction{
		Arguments: [][]byte{arg},
		Nonce:     nonce,
		Type:      raw.TransactionType_UPLOAD_FILE,
	}, nil
}

// UploadFileResponse represents the /api/v1/UploadFile response.
type UploadFileResponse struct {
	FileID string `json:"fileId"`
}
