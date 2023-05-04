package archethic

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
)

// type TransactionType uint8

type TransactionType uint8

const (
	Version            uint32          = 1
	KeychainAccessType TransactionType = 254
	KeychainType       TransactionType = 255
	TransferType       TransactionType = 253
	HostingType        TransactionType = 252
	TokenType          TransactionType = 251
	DataType           TransactionType = 250
	ContractType       TransactionType = 249
	CodeProposalType   TransactionType = 5
	CodeApprovalType   TransactionType = 6
)

type TransactionBuilder struct {
	Version           uint32
	Address           []byte
	TxType            TransactionType
	Data              TransactionData
	PreviousPublicKey []byte
	PreviousSignature []byte
	OriginSignature   []byte
}

type TransactionData struct {
	Content    []byte
	Code       []byte
	Ledger     Ledger
	Ownerships []Ownership
	Recipients [][]byte
}

func (t TransactionData) toBytes() []byte {
	buf := make([]byte, 0)

	// Encode code
	buf = appendSizeAndContent(buf, t.Code, 32)

	// Encode content
	buf = appendSizeAndContent(buf, t.Content, 32)

	// Encode ownerships
	buf = append(buf, t.ownershipsBytes()...)

	// Encode ledger (UCO + token)
	buf = append(buf, t.Ledger.toBytes()...)

	// Encode recipients
	recipientsBytes := make([]byte, 0)
	for i := 0; i < len(t.Recipients); i++ {
		recipientsBytes = append(recipientsBytes, t.Recipients[i]...)
	}
	size, recipientSize := convertToMinimumBytes(len(t.Recipients))
	buf = append(buf, byte(size))
	buf = append(buf, recipientSize...)

	buf = append(buf, recipientsBytes...)

	return buf
}

func (t TransactionData) ownershipsBytes() []byte {
	buf := make([]byte, 0)

	size, ownerShipSize := convertToMinimumBytes(len(t.Ownerships))
	buf = append(buf, byte(size))
	buf = append(buf, ownerShipSize...)

	for i := 0; i < len(t.Ownerships); i++ {
		buf = append(buf, t.Ownerships[i].toBytes()...)
	}
	return buf
}

type Ledger struct {
	Uco   UcoLedger
	Token TokenLedger
}

func (l Ledger) toBytes() []byte {
	buf := make([]byte, 0)
	buf = append(buf, l.Uco.toBytes()...)
	buf = append(buf, l.Token.toBytes()...)
	return buf
}

type UcoLedger struct {
	Transfers []UcoTransfer
}

func (l UcoLedger) toBytes() []byte {
	buf := make([]byte, 0)

	ucoBytes := make([]byte, 0)
	for i := 0; i < len(l.Transfers); i++ {
		ucoBytes = append(ucoBytes, l.Transfers[i].toBytes()...)
	}

	size, transferSize := convertToMinimumBytes(len(l.Transfers))
	buf = append(buf, byte(size))
	buf = append(buf, transferSize...)
	buf = append(buf, ucoBytes...)
	return buf
}

type UcoTransfer struct {
	To     []byte
	Amount uint64
}

func (t UcoTransfer) toBytes() []byte {
	buf := make([]byte, 0)
	buf = append(buf, t.To...)

	amountBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(amountBytes, t.Amount)

	buf = append(buf, amountBytes...)
	return buf
}

type TokenLedger struct {
	Transfers []TokenTransfer
}

func (l TokenLedger) toBytes() []byte {
	buf := make([]byte, 0)

	tokenBytes := make([]byte, 0)
	for i := 0; i < len(l.Transfers); i++ {
		tokenBytes = append(tokenBytes, l.Transfers[i].toBytes()...)
	}

	size, transferSize := convertToMinimumBytes(len(l.Transfers))
	buf = append(buf, byte(size))
	buf = append(buf, transferSize...)
	buf = append(buf, tokenBytes...)
	return buf
}

type TokenTransfer struct {
	To           []byte
	TokenAddress []byte
	TokenId      int
	Amount       uint64
}

func (t TokenTransfer) toBytes() []byte {
	buf := make([]byte, 0)
	buf = append(buf, t.TokenAddress...)
	buf = append(buf, t.To...)

	amountBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(amountBytes, t.Amount)
	buf = append(buf, amountBytes...)

	size, tokenIdByte := convertToMinimumBytes(t.TokenId)
	buf = append(buf, byte(size))
	buf = append(buf, tokenIdByte...)

	return buf
}

type Ownership struct {
	Secret         []byte
	AuthorizedKeys []AuthorizedKey
}

func (o Ownership) toBytes() []byte {
	buf := make([]byte, 0)

	buf = appendSizeAndContent(buf, o.Secret, 32)

	authorizedKeysBuf := make([]byte, 0)
	for j := 0; j < len(o.AuthorizedKeys); j++ {
		authorizedKey := o.AuthorizedKeys[j]
		authorizedKeysBuf = append(authorizedKeysBuf, authorizedKey.PublicKey...)
		authorizedKeysBuf = append(authorizedKeysBuf, authorizedKey.EncryptedSecretKey...)
	}

	size, authorizedKeySize := convertToMinimumBytes(len(o.AuthorizedKeys))
	buf = append(buf, byte(size))
	buf = append(buf, authorizedKeySize...)
	buf = append(buf, authorizedKeysBuf...)

	return buf
}

type AuthorizedKey struct {
	PublicKey          []byte
	EncryptedSecretKey []byte
}

// New transaction builder instance
func NewTransaction(txType TransactionType) *TransactionBuilder {
	return &TransactionBuilder{
		Version: Version,
		TxType:  txType,
		Data: TransactionData{
			Code:    []byte{},
			Content: []byte{},
			Ledger: Ledger{
				Uco: UcoLedger{
					Transfers: []UcoTransfer{},
				},
				Token: TokenLedger{
					Transfers: []TokenTransfer{},
				},
			},
			Ownerships: []Ownership{},
			Recipients: [][]byte{},
		},
	}
}

func (t *TransactionBuilder) SetContent(content []byte) {
	t.Data.Content = content
}

func (t *TransactionBuilder) SetCode(code string) {
	t.Data.Code = []byte(code)
}

func (t *TransactionBuilder) SetType(txType TransactionType) {
	t.TxType = txType
}

func (t *TransactionBuilder) SetAddress(address []byte) {
	t.Address = address
}

func (t *TransactionBuilder) AddUcoTransfer(to []byte, amount uint64) {
	t.Data.Ledger.Uco.Transfers = append(t.Data.Ledger.Uco.Transfers, UcoTransfer{
		To:     to,
		Amount: amount,
	})
}

func (t *TransactionBuilder) AddTokenTransfer(to []byte, tokenAddress []byte, amount uint64, tokenId int) {
	t.Data.Ledger.Token.Transfers = append(t.Data.Ledger.Token.Transfers, TokenTransfer{
		To:           to,
		TokenAddress: tokenAddress,
		Amount:       amount,
		TokenId:      tokenId,
	})
}

func (t *TransactionBuilder) AddRecipient(address []byte) {
	t.Data.Recipients = append(t.Data.Recipients, address)
}

func (t *TransactionBuilder) AddOwnership(secret []byte, authorizedKeys []AuthorizedKey) {

	filteredAuthorizedKeys := make([]AuthorizedKey, 0)

	var emptyAcc = make(map[string]interface{})

	// Remove duplicated public key
	for _, k := range authorizedKeys {
		publicKey := k.PublicKey
		encryptedSecretKey := k.EncryptedSecretKey

		if _, ok := emptyAcc[string(publicKey)]; !ok {
			filteredAuthorizedKeys = append(filteredAuthorizedKeys, AuthorizedKey{
				PublicKey:          publicKey,
				EncryptedSecretKey: encryptedSecretKey,
			})
		}

		emptyAcc[string(publicKey)] = encryptedSecretKey
	}

	t.Data.Ownerships = append(t.Data.Ownerships, Ownership{
		Secret:         secret,
		AuthorizedKeys: filteredAuthorizedKeys,
	})
}

func (t *TransactionBuilder) Build(seed []byte, index uint32, curve Curve, hashAlgo HashAlgo) error {
	publicKey, privateKey, err := DeriveKeypair(seed, index, curve)
	if err != nil {
		return err
	}
	address, err := DeriveAddress(seed, index+1, curve, hashAlgo)
	if err != nil {
		return err
	}

	t.Address = address
	t.PreviousPublicKey = publicKey
	t.PreviousSignature, err = Sign(privateKey, t.previousSignaturePayload())
	if err != nil {
		return err
	}
	return nil
}

func (t *TransactionBuilder) OriginSign(originPrivateKey []byte) error {
	originSignature, err := Sign(originPrivateKey, t.OriginSignaturePayload())
	t.OriginSignature = originSignature
	if err != nil {
		return err
	}
	return nil
}

func (t TransactionBuilder) previousSignaturePayload() []byte {
	versionBytes := []byte{0, 0, 0, 0}

	binary.BigEndian.PutUint32(versionBytes, t.Version)

	buf := make([]byte, 0)

	buf = append(buf, versionBytes...)
	buf = append(buf, t.Address...)
	buf = append(buf, byte(t.TxType))
	buf = append(buf, t.Data.toBytes()...)

	return buf
}

func (tx *TransactionBuilder) SetPreviousSignatureAndPreviousPublicKey(prevSign []byte, prevPubKey []byte) {
	tx.PreviousPublicKey = prevPubKey
	tx.PreviousSignature = prevSign
}

func (t TransactionBuilder) OriginSignaturePayload() []byte {
	buf := make([]byte, 0)
	buf = append(buf, t.PreviousPublicKey...)
	buf = appendSizeAndContent(buf, t.PreviousSignature, 8)

	return append(t.previousSignaturePayload(), buf...)
}

func appendSizeAndContent(buf []byte, input []byte, bitSize int) []byte {
	switch bitSize {
	case 8:
		buf = append(buf, byte(len(input)))
	case 32:
		buf = append(buf, EncodeInt32(uint32(len(input)))...)
	case 64:
		buf = append(buf, EncodeInt64(uint64(len(input)))...)
	}
	buf = append(buf, input...)
	return buf
}

func convertToMinimumBytes(length int) (int, []byte) {

	// determine the minimum number of bytes necessary to represent the length
	var size int
	switch {
	case length <= 0xff:
		size = 1
	case length <= 0xffff:
		size = 2
	case length <= 0xffffff:
		size = 3
	case length <= 0xffffffff:
		size = 4
	case length <= 0xffffffffff:
		size = 5
	case length <= 0xffffffffffff:
		size = 6
	case length <= 0xffffffffffffff:
		size = 7
	default:
		size = 8
	}

	// create a byte slice of the appropriate size
	bytes := make([]byte, size)

	// convert the uint64 length to bytes and store it in the byte slice
	switch size {
	case 1:
		bytes[0] = byte(length)
	case 2:
		binary.BigEndian.PutUint16(bytes, uint16(length))
	case 3:
		bytes[0] = byte(length & 0xff)
		bytes[1] = byte((length >> 8) & 0xff)
		bytes[2] = byte((length >> 16) & 0xff)
	case 4:
		binary.BigEndian.PutUint32(bytes, uint32(length))
	case 5:
		bytes[0] = byte(length & 0xff)
		bytes[1] = byte((length >> 8) & 0xff)
		bytes[2] = byte((length >> 16) & 0xff)
		bytes[3] = byte((length >> 24) & 0xff)
		bytes[4] = byte((length >> 32) & 0xff)
	case 6:
		bytes[0] = byte(length & 0xff)
		bytes[1] = byte((length >> 8) & 0xff)
		bytes[2] = byte((length >> 16) & 0xff)
		bytes[3] = byte((length >> 24) & 0xff)
		bytes[4] = byte((length >> 32) & 0xff)
		bytes[5] = byte((length >> 40) & 0xff)
	case 7:
		bytes[0] = byte(length & 0xff)
		bytes[1] = byte((length >> 8) & 0xff)
		bytes[2] = byte((length >> 16) & 0xff)
		bytes[3] = byte((length >> 24) & 0xff)
		bytes[4] = byte((length >> 32) & 0xff)
		bytes[5] = byte((length >> 40) & 0xff)
		bytes[6] = byte((length >> 48) & 0xff)
	default:
		binary.BigEndian.PutUint64(bytes, uint64(length))
	}
	return size, bytes
}

func ToUint64(number float64, decimals int) (uint64, error) {
	if decimals < 0 {
		return 0, errors.New("'decimals' must be a non-negative integer")
	}

	factor := math.Pow10(decimals)
	result := uint64(number * factor)

	return result, nil
}

func (t *TransactionBuilder) ToJSON() ([]byte, error) {
	ownerships := make([]map[string]interface{}, len(t.Data.Ownerships))
	for i, o := range t.Data.Ownerships {
		authorizedKeys := make([]map[string]string, len(o.AuthorizedKeys))
		for j, a := range o.AuthorizedKeys {
			authorizedKeys[j] = map[string]string{
				"publicKey":          hex.EncodeToString(a.PublicKey),
				"encryptedSecretKey": hex.EncodeToString(a.EncryptedSecretKey),
			}
		}
		ownerships[i] = map[string]interface{}{
			"secret":         hex.EncodeToString(o.Secret),
			"authorizedKeys": authorizedKeys,
		}
	}
	ucoTransfers := make([]map[string]interface{}, len(t.Data.Ledger.Uco.Transfers))
	for i, t := range t.Data.Ledger.Uco.Transfers {
		ucoTransfers[i] = map[string]interface{}{
			"to":     hex.EncodeToString(t.To),
			"amount": t.Amount,
		}
	}
	tokenTransfers := make([]map[string]interface{}, len(t.Data.Ledger.Token.Transfers))
	for i, t := range t.Data.Ledger.Token.Transfers {
		tokenTransfers[i] = map[string]interface{}{
			"to":           hex.EncodeToString(t.To),
			"amount":       t.Amount,
			"tokenAddress": hex.EncodeToString(t.TokenAddress),
			"tokenId":      t.TokenId,
		}
	}
	recipients := make([]string, len(t.Data.Recipients))
	for i, r := range t.Data.Recipients {
		recipients[i] = hex.EncodeToString(r)
	}
	data := map[string]interface{}{
		"content":    hex.EncodeToString(t.Data.Content),
		"code":       string(t.Data.Code),
		"ownerships": ownerships,
		"ledger": map[string]interface{}{
			"uco": map[string]interface{}{
				"transfers": ucoTransfers,
			},
			"token": map[string]interface{}{
				"transfers": tokenTransfers,
			},
		},
		"recipients": recipients,
	}
	txType, err := t.TxType.String()
	if err != nil {
		return nil, err
	}
	m := map[string]interface{}{
		"version":           t.Version,
		"address":           hex.EncodeToString(t.Address),
		"type":              txType,
		"data":              data,
		"previousPublicKey": hex.EncodeToString(t.PreviousPublicKey),
		"previousSignature": hex.EncodeToString(t.PreviousSignature),
		"originSignature":   nil,
	}
	if t.OriginSignature != nil {
		m["originSignature"] = hex.EncodeToString(t.OriginSignature)
	}
	return json.Marshal(m)
}

func (t TransactionType) String() (string, error) {
	switch t {
	case KeychainAccessType:
		return "keychain_access", nil
	case KeychainType:
		return "keychain", nil
	case TransferType:
		return "transfer", nil
	case HostingType:
		return "hosting", nil
	case TokenType:
		return "token", nil
	case DataType:
		return "data", nil
	case ContractType:
		return "contract", nil
	case CodeProposalType:
		return "code_proposal", nil
	case CodeApprovalType:
		return "code_approval", nil
	}
	return "", errors.New("unknown transaction type")
}
