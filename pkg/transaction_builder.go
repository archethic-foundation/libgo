package archethic

import (
	"encoding/binary"
)

type TransactionType uint8

const (
	KeychainType       TransactionType = 255
	KeychainAccessType TransactionType = 254
	TransferType       TransactionType = 253
	NFTType            TransactionType = 252
	HostingType        TransactionType = 251
	DataType           TransactionType = 250
	ContractType       TransactionType = 249
	CodeProposalType   TransactionType = 5
	CodeApprovalType   TransactionType = 6
	Version            uint32          = 1
)

type TransactionBuilder struct {
	version           uint32
	address           []byte
	txType            TransactionType
	data              TransactionData
	previousPublicKey []byte
	previousSignature []byte
	originSignature   []byte
}

type TransactionData struct {
	content    []byte
	code       []byte
	ledger     Ledger
	ownerships []Ownership
	recipients [][]byte
}

func (t TransactionData) toBytes() []byte {
	buf := make([]byte, 0)

	// Encode code
	buf = appendSizeAndContent(buf, t.code, 32)

	// Encode content
	buf = appendSizeAndContent(buf, t.content, 32)

	// Encode ownerships
	buf = append(buf, t.ownershipsBytes()...)

	// Encode ledger (UCO + token)
	buf = append(buf, t.ledger.toBytes()...)

	// Encode recipients
	recipientsBytes := make([]byte, 0)
	for i := 0; i < len(t.recipients); i++ {
		recipientsBytes = append(recipientsBytes, t.recipients[i]...)
	}
	size, recipientSize := convertToMinimumBytes(len(t.ownerships))
	buf = append(buf, byte(size))
	buf = append(buf, recipientSize...)

	buf = append(buf, recipientsBytes...)

	return buf
}

func (t TransactionData) ownershipsBytes() []byte {
	buf := make([]byte, 0)

	size, ownerShipSize := convertToMinimumBytes(len(t.ownerships))
	buf = append(buf, byte(size))
	buf = append(buf, ownerShipSize...)

	for i := 0; i < len(t.ownerships); i++ {
		buf = append(buf, t.ownerships[i].toBytes()...)
	}
	return buf
}

type Ledger struct {
	uco   UcoLedger
	token TokenLedger
}

func (l Ledger) toBytes() []byte {
	buf := make([]byte, 0)
	buf = append(buf, l.uco.toBytes()...)
	buf = append(buf, l.token.toBytes()...)
	return buf
}

type UcoLedger struct {
	transfers []UcoTransfer
}

func (l UcoLedger) toBytes() []byte {
	buf := make([]byte, 0)

	ucoBytes := make([]byte, 0)
	for i := 0; i < len(l.transfers); i++ {
		ucoBytes = append(ucoBytes, l.transfers[i].toBytes()...)
	}

	size, transferSize := convertToMinimumBytes(len(l.transfers))
	buf = append(buf, byte(size))
	buf = append(buf, transferSize...)
	buf = append(buf, ucoBytes...)
	return buf
}

type UcoTransfer struct {
	to     []byte
	amount uint64
}

func (t UcoTransfer) toBytes() []byte {
	buf := make([]byte, 0)
	buf = append(buf, t.to...)

	amountBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(amountBytes, t.amount)

	buf = append(buf, amountBytes...)
	return buf
}

type TokenLedger struct {
	transfers []TokenTransfer
}

func (l TokenLedger) toBytes() []byte {
	buf := make([]byte, 0)

	tokenBytes := make([]byte, 0)
	for i := 0; i < len(l.transfers); i++ {
		tokenBytes = append(tokenBytes, l.transfers[i].toBytes()...)
	}

	size, transferSize := convertToMinimumBytes(len(l.transfers))
	buf = append(buf, byte(size))
	buf = append(buf, transferSize...)
	buf = append(buf, tokenBytes...)
	return buf
}

type TokenTransfer struct {
	to           []byte
	tokenAddress []byte
	tokenId      int
	amount       uint64
}

func (t TokenTransfer) toBytes() []byte {
	buf := make([]byte, 0)
	buf = append(buf, t.tokenAddress...)
	buf = append(buf, t.to...)

	amountBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(amountBytes, t.amount)
	buf = append(buf, amountBytes...)

	size, tokenIdByte := convertToMinimumBytes(t.tokenId)
	buf = append(buf, byte(size))
	buf = append(buf, tokenIdByte...)

	return buf
}

type Ownership struct {
	secret         []byte
	authorizedKeys []AuthorizedKey
}

func (o Ownership) toBytes() []byte {
	buf := make([]byte, 0)

	buf = appendSizeAndContent(buf, o.secret, 32)

	authorizedKeysBuf := make([]byte, 0)
	for j := 0; j < len(o.authorizedKeys); j++ {
		authorizedKey := o.authorizedKeys[j]
		authorizedKeysBuf = append(authorizedKeysBuf, authorizedKey.publicKey...)
		authorizedKeysBuf = append(authorizedKeysBuf, authorizedKey.encryptedSecretKey...)
	}

	size, authorizedKeySize := convertToMinimumBytes(len(o.authorizedKeys))
	buf = append(buf, byte(size))
	buf = append(buf, authorizedKeySize...)
	buf = append(buf, authorizedKeysBuf...)

	return buf
}

type AuthorizedKey struct {
	publicKey          []byte
	encryptedSecretKey []byte
}

// New transaction builder instance
func New(txType TransactionType) *TransactionBuilder {
	return &TransactionBuilder{
		version: Version,
		txType:  txType,
		data: TransactionData{
			code:    []byte{},
			content: []byte{},
			ledger: Ledger{
				uco: UcoLedger{
					transfers: []UcoTransfer{},
				},
				token: TokenLedger{
					transfers: []TokenTransfer{},
				},
			},
			ownerships: []Ownership{},
			recipients: [][]byte{},
		},
	}
}

func (t *TransactionBuilder) SetContent(content []byte) {
	t.data.content = content
}

func (t *TransactionBuilder) SetCode(code string) {
	t.data.code = []byte(code)
}

func (t *TransactionBuilder) SetType(txType TransactionType) {
	t.txType = txType
}

func (t *TransactionBuilder) SetAddress(address []byte) {
	t.address = address
}

func (t *TransactionBuilder) AddUcoTransfer(to []byte, amount uint64) {
	t.data.ledger.uco.transfers = append(t.data.ledger.uco.transfers, UcoTransfer{
		to:     to,
		amount: amount,
	})
}

func (t *TransactionBuilder) AddTokenTransfer(to []byte, tokenAddress []byte, amount uint64, tokenId int) {
	t.data.ledger.token.transfers = append(t.data.ledger.token.transfers, TokenTransfer{
		to:           to,
		tokenAddress: tokenAddress,
		amount:       amount,
		tokenId:      tokenId,
	})
}

func (t *TransactionBuilder) AddRecipient(address []byte) {
	t.data.recipients = append(t.data.recipients, address)
}

func (t *TransactionBuilder) AddOwnership(secret []byte, authorizedKeys []AuthorizedKey) {

	filteredAuthorizedKeys := make([]AuthorizedKey, 0)

	var emptyAcc = make(map[string]interface{})

	// Remove duplicated public key
	for _, k := range authorizedKeys {
		publicKey := k.publicKey
		encryptedSecretKey := k.encryptedSecretKey

		if _, ok := emptyAcc[string(publicKey)]; !ok {
			filteredAuthorizedKeys = append(filteredAuthorizedKeys, AuthorizedKey{
				publicKey:          publicKey,
				encryptedSecretKey: encryptedSecretKey,
			})
		}

		emptyAcc[string(publicKey)] = encryptedSecretKey
	}

	t.data.ownerships = append(t.data.ownerships, Ownership{
		secret:         secret,
		authorizedKeys: filteredAuthorizedKeys,
	})
}

func (t *TransactionBuilder) Build(seed []byte, index uint32, curve Curve, hashAlgo HashAlgo) {
	publicKey, privateKey := DeriveKeypair(seed, index, curve)
	address := DeriveAddress(seed, index+1, curve, hashAlgo)

	t.address = address
	t.previousSignature = Sign(privateKey, t.previousSignaturePayload())
	t.previousPublicKey = publicKey
}

func (t *TransactionBuilder) OriginSign(originPrivateKey []byte) {
	t.originSignature = Sign(originPrivateKey, t.originSignaturePayload())
}

func (t TransactionBuilder) previousSignaturePayload() []byte {
	versionBytes := []byte{0, 0, 0, 0}

	binary.LittleEndian.PutUint32(versionBytes, t.version)

	buf := make([]byte, 0)

	buf = append(buf, versionBytes...)
	buf = append(buf, t.address...)
	buf = append(buf, byte(t.txType))
	buf = append(buf, t.data.toBytes()...)

	return buf
}

func (tx *TransactionBuilder) SetPreviousSignatureAndPreviousPublicKey(prevSign []byte, prevPubKey []byte) {
	tx.previousPublicKey = prevPubKey
	tx.previousSignature = prevSign
}

func (t TransactionBuilder) originSignaturePayload() []byte {
	buf := make([]byte, 0)
	buf = append(buf, t.previousPublicKey...)
	buf = appendSizeAndContent(buf, t.previousSignature, 8)

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
		binary.LittleEndian.PutUint16(bytes, uint16(length))
	case 3:
		bytes[0] = byte(length & 0xff)
		bytes[1] = byte((length >> 8) & 0xff)
		bytes[2] = byte((length >> 16) & 0xff)
	case 4:
		binary.LittleEndian.PutUint32(bytes, uint32(length))
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
		binary.LittleEndian.PutUint64(bytes, uint64(length))
	}
	return size, bytes
}
