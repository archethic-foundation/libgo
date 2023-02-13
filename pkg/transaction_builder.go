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
	code       string
	ledger     Ledger
	ownerships []Ownership
	recipients [][]byte
}

func (t TransactionData) toBytes() []byte {
	buf := make([]byte, 0)
	buf = append(buf, byte(len(t.code)))
	buf = append(buf, []byte(t.code)...)
	buf = append(buf, byte(len(t.content)))
	buf = append(buf, t.content...)
	buf = append(buf, t.ownershipsBytes()...)
	buf = append(buf, t.toBytes()...)
	buf = append(buf, byte(len(t.recipients)))
	buf = append(buf, concatAppend(t.recipients)...)

	return buf
}

func (t TransactionData) ownershipsBytes() []byte {
	buf := make([]byte, 0)
	for i := 0; i < len(t.ownerships); i++ {
		buf = append(buf, t.ownerships[i].toBytes()...)
	}
	return buf
}

type Ledger struct {
	uco UcoLedger
	nft NftLedger
}

func (l Ledger) toBytes() []byte {
	buf := make([]byte, 0)
	buf = append(buf, l.uco.toBytes()...)
	buf = append(buf, l.nft.toBytes()...)
	return buf
}

type UcoLedger struct {
	transfers []UcoTransfer
}

func (l UcoLedger) toBytes() []byte {
	buf := make([]byte, 0)
	buf = append(buf, byte(len(l.transfers)))

	for i := 0; i < len(l.transfers); i++ {
		buf = append(buf, l.transfers[i].toBytes()...)
	}
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

type NftLedger struct {
	transfers []NftTransfer
}

func (l NftLedger) toBytes() []byte {
	buf := make([]byte, 0)
	buf = append(buf, byte(len(l.transfers)))

	for i := 0; i < len(l.transfers); i++ {
		buf = append(buf, l.transfers[i].toBytes()...)
	}
	return buf
}

type NftTransfer struct {
	to     []byte
	nft    []byte
	amount uint64
}

func (t NftTransfer) toBytes() []byte {
	buf := make([]byte, 0)
	buf = append(buf, t.to...)
	buf = append(buf, t.nft...)

	amountBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(amountBytes, t.amount)

	buf = append(buf, amountBytes...)
	return buf
}

type Ownership struct {
	secret         []byte
	authorizedKeys []AuthorizedKey
}

func (o Ownership) toBytes() []byte {
	buf := make([]byte, 0)

	authorizedKeysBuf := make([]byte, 0)
	for j := 0; j < len(o.authorizedKeys); j++ {
		authorizedKey := o.authorizedKeys[j]
		authorizedKeysBuf = append(authorizedKeysBuf, authorizedKey.publicKey...)
		authorizedKeysBuf = append(authorizedKeysBuf, authorizedKey.encryptedSecretKey...)
	}

	buf = append(buf, byte(len(o.secret)))
	buf = append(buf, o.secret...)
	buf = append(buf, byte(len(o.authorizedKeys)))
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
		txType: txType,
		data: TransactionData{
			code:    "",
			content: []byte{},
			ledger: Ledger{
				uco: UcoLedger{
					transfers: []UcoTransfer{},
				},
				nft: NftLedger{
					transfers: []NftTransfer{},
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
	t.data.code = code
}

func (t *TransactionBuilder) AddUcoTransfer(to []byte, amount uint64) {
	t.data.ledger.uco.transfers = append(t.data.ledger.uco.transfers, UcoTransfer{
		to:     to,
		amount: amount,
	})
}

func (t *TransactionBuilder) AddNftTransfer(to []byte, nft []byte, amount uint64) {
	t.data.ledger.nft.transfers = append(t.data.ledger.nft.transfers, NftTransfer{
		to:     to,
		nft:    nft,
		amount: amount,
	})
}

func (t *TransactionBuilder) AddContractRecipient(address []byte) {
	t.data.recipients = append(t.data.recipients, address)
}

func (t *TransactionBuilder) AddOwnership(secret []byte, authorizedKeys []AuthorizedKey) {
	t.data.ownerships = append(t.data.ownerships, Ownership{
		secret:         secret,
		authorizedKeys: authorizedKeys,
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

func (t TransactionBuilder) originSignaturePayload() []byte {
	buf := make([]byte, 0)
	buf = append(buf, t.previousPublicKey...)
	buf = append(buf, byte(len(t.previousSignature)))
	buf = append(buf, t.previousSignature...)

	return append(t.previousSignaturePayload(), buf...)
}

func concatAppend(slices [][]byte) []byte {
	var tmp []byte
	for _, s := range slices {
		tmp = append(tmp, s...)
	}
	return tmp
}
