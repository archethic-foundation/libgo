package archethic

import (
	"encoding/hex"
	"reflect"
	"testing"
)

func TestSetType(t *testing.T) {
	tx := TransactionBuilder{}
	tx.SetType(TransferType)
	if tx.TxType != TransferType {
		t.Errorf("expected tx type to be TransferType, got %v", tx.TxType)
	}

	tx = TransactionBuilder{}
	tx.SetType(ContractType)
	if tx.TxType != ContractType {
		t.Errorf("expected tx type to be KeychainAccessType, got %v", tx.TxType)
	}

	tx = TransactionBuilder{}
	tx.SetType(DataType)
	if tx.TxType != DataType {
		t.Errorf("expected tx type to be KeychainType, got %v", tx.TxType)
	}

	tx = TransactionBuilder{}
	tx.SetType(TokenType)
	if tx.TxType != TokenType {
		t.Errorf("expected tx type to be TokenType, got %v", tx.TxType)
	}

	tx = TransactionBuilder{}
	tx.SetType(HostingType)
	if tx.TxType != HostingType {
		t.Errorf("expected tx type to be HostingType, got %v", tx.TxType)
	}

	tx = TransactionBuilder{}
	tx.SetType(CodeProposalType)
	if tx.TxType != CodeProposalType {
		t.Errorf("expected tx type to be CodeProposalType, got %v", tx.TxType)
	}

	tx = TransactionBuilder{}
	tx.SetType(CodeApprovalType)
	if tx.TxType != CodeApprovalType {
		t.Errorf("expected tx type to be CodeApprovalType, got %v", tx.TxType)
	}
}

func TestTransactionBuilder_SetCode(t *testing.T) {
	tx := TransactionBuilder{
		TxType: TransferType,
	}
	tx.SetCode("my smart contract code") // "my smart contract code" in hex

	if !reflect.DeepEqual(string(tx.Data.Code), "my smart contract code") {
		t.Errorf("Failed to set transaction code")
	}
}

func TestTransactionBuilder_SetContent(t *testing.T) {
	tx := TransactionBuilder{
		TxType: TransferType,
	}
	tx.SetContent([]byte("my super content"))

	expectedContent := []byte("my super content")
	if !reflect.DeepEqual(tx.Data.Content, expectedContent) {
		t.Errorf("Failed to set transaction content")
	}
}

func TestAddOwnership(t *testing.T) {
	tx := TransactionBuilder{TxType: TransferType}
	tx.AddOwnership(
		[]byte("00501fa2db78bcf8ceca129e6139d7e38bf0d61eb905441056b9ebe6f1d1feaf88"),
		[]AuthorizedKey{
			{
				PublicKey:          []byte("0001b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646"),
				EncryptedSecretKey: []byte("00501fa2db78bcf8ceca129e6139d7e38bf0d61eb905441056b9ebe6f1d1feaf88"),
			},
			{
				PublicKey:          []byte("0001b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646"),
				EncryptedSecretKey: []byte("00601fa2db78bcf8ceca129e6139d7e38bf0d61eb905441056b9ebe6f1d1feaf88"),
			},
		},
	)

	expectedContent := []AuthorizedKey{{
		PublicKey:          []byte("0001b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646"),
		EncryptedSecretKey: []byte("00501fa2db78bcf8ceca129e6139d7e38bf0d61eb905441056b9ebe6f1d1feaf88"),
	}}
	if !reflect.DeepEqual(tx.Data.Ownerships[0].AuthorizedKeys, expectedContent) {
		t.Errorf("Failed to set transaction authorized key")
	}
	if !reflect.DeepEqual(tx.Data.Ownerships[0].Secret, []byte("00501fa2db78bcf8ceca129e6139d7e38bf0d61eb905441056b9ebe6f1d1feaf88")) {
		t.Errorf("Failed to set transaction secret")
	}
}
func TestAddUCOTransfer(t *testing.T) {
	tx := TransactionBuilder{TxType: TransferType}
	amount, _ := ToUint64(10.03, 8)
	tx.AddUcoTransfer(
		[]byte("0000b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646"),
		amount,
	)

	if len(tx.Data.Ledger.Uco.Transfers) != 1 {
		t.Errorf("expected one transfer, got %d", len(tx.Data.Ledger.Uco.Transfers))
	}

	expectedTo := []byte("0000b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646")
	if !reflect.DeepEqual(tx.Data.Ledger.Uco.Transfers[0].To, expectedTo) {
		t.Errorf("expected to address %v, got %v", expectedTo, tx.Data.Ledger.Uco.Transfers[0].To)
	}

	expectedAmount, _ := ToUint64(10.03, 8)
	if tx.Data.Ledger.Uco.Transfers[0].Amount != expectedAmount {
		t.Errorf("expected amount %d, got %d", expectedAmount, tx.Data.Ledger.Uco.Transfers[0].Amount)
	}
}

func TestAddTokenTransfer(t *testing.T) {

	tx := TransactionBuilder{TxType: TransferType}
	amount, _ := ToUint64(10.03, 8)
	tx.AddTokenTransfer(
		[]byte("0000b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646"),
		[]byte("0000b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646"),
		amount,
		1,
	)

	if len(tx.Data.Ledger.Token.Transfers) != 1 {
		t.Errorf("expected one transfer, got %d", len(tx.Data.Ledger.Token.Transfers))
	}

	expectedTo := []byte("0000b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646")
	if !reflect.DeepEqual(tx.Data.Ledger.Token.Transfers[0].To, expectedTo) {
		t.Errorf("expected to address %v, got %v", expectedTo, tx.Data.Ledger.Token.Transfers[0].To)
	}

	expectedTokenAddress := []byte("0000b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646")
	if !reflect.DeepEqual(tx.Data.Ledger.Token.Transfers[0].TokenAddress, expectedTokenAddress) {
		t.Errorf("expected to token address %v, got %v", expectedTo, tx.Data.Ledger.Token.Transfers[0].TokenAddress)
	}

	expectedAmount, _ := ToUint64(10.03, 8)
	if tx.Data.Ledger.Token.Transfers[0].Amount != expectedAmount {
		t.Errorf("expected amount %d, got %d", expectedAmount, tx.Data.Ledger.Token.Transfers[0].Amount)
	}
}

func TestPreviousSignaturePayload(t *testing.T) {
	code := `
        condition inherit: [
            uco_transferred: 0.020
        ]

        actions triggered by: transaction do
            set_type transfer
            add_uco_ledger to: "000056E763190B28B4CF9AAF3324CF379F27DE9EF7850209FB59AA002D71BA09788A", amount: 0.020
        end
    `
	content := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec sit amet leo egestas, lobortis lectus a, dignissim orci.")
	secret := []byte("mysecret")

	tx := NewTransaction(TransferType)
	tx.AddOwnership(
		secret,
		[]AuthorizedKey{
			{
				PublicKey:          []byte("0001b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646"),
				EncryptedSecretKey: []byte("00501fa2db78bcf8ceca129e6139d7e38bf0d61eb905441056b9ebe6f1d1feaf88"),
			},
			// {
			// 	publicKey:          []byte("0001a1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646"),
			// 	encryptedSecretKey: []byte("00501fa2db78bcf8ceca129e6139d7e38bf0d61eb905441056b9ebe6f1d1feaf88"),
			// },
		},
	)

	amount, _ := ToUint64(0.202, 8)
	amount2, _ := ToUint64(100, 8)
	tx.AddUcoTransfer(
		[]byte("0000b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646"),
		amount)
	tx.AddTokenTransfer(
		[]byte("0000b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646"),
		[]byte("0000501fa2db78bcf8ceca129e6139d7e38bf0d61eb905441056b9ebe6f1d1feaf88"),
		amount2,
		1)
	tx.SetCode(code)
	tx.SetContent(content)

	// a unnamed action
	tx.AddRecipient(
		[]byte("0000501fa2db78bcf8ceca129e6139d7e38bf0d61eb905441056b9ebe6f1d1feaf88"))

	// a named action
	tx.AddRecipientForNamedAction(
		[]byte("0000501fa2db78bcf8ceca129e6139d7e38bf0d61eb905441056b9ebe6f1d1feaf88"),
		[]byte("vote_for_class_president"),
		[]byte("[\"Judy\"]"))

	publicKey, _, _ := DeriveKeypair([]byte("seed"), 0, ED25519)
	address, _ := DeriveAddress([]byte("seed"), 1, ED25519, SHA256)

	tx.Address = address
	tx.PreviousPublicKey = publicKey

	payload := tx.previousSignaturePayload()

	expectedBinary := make([]byte, 0)
	// Version
	expectedBinary = append(expectedBinary, EncodeInt32(2)...)
	expectedBinary = append(expectedBinary, tx.Address...)
	expectedBinary = append(expectedBinary, []byte{253}...)

	// Code size
	expectedBinary = append(expectedBinary, EncodeInt32(uint32(len(code)))...)
	expectedBinary = append(expectedBinary, []byte(code)...)

	// Content size
	expectedBinary = append(expectedBinary, EncodeInt32(uint32(len(content)))...)
	expectedBinary = append(expectedBinary, []byte(content)...)

	// Nb of byte to encode nb of ownerships
	expectedBinary = append(expectedBinary, []byte{1}...)

	// Nb ownerships
	expectedBinary = append(expectedBinary, []byte{1}...)

	// Secret size
	expectedBinary = append(expectedBinary, EncodeInt32(uint32(len(secret)))...)
	expectedBinary = append(expectedBinary, []byte(secret)...)

	// Nb of byte to encode nb of authorized key
	expectedBinary = append(expectedBinary, []byte{1}...)

	// Nb of authorized keys
	expectedBinary = append(expectedBinary, []byte{1}...)

	// Authorized keys encoding
	expectedBinary = append(expectedBinary, []byte("0001b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646")...)
	expectedBinary = append(expectedBinary, []byte("00501fa2db78bcf8ceca129e6139d7e38bf0d61eb905441056b9ebe6f1d1feaf88")...)

	// Nb of byte to encode nb of uco transfers
	expectedBinary = append(expectedBinary, []byte{1}...)

	// Nb of uco transfers
	expectedBinary = append(expectedBinary, []byte{1}...)
	expectedBinary = append(expectedBinary, []byte("0000b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646")...)
	amount, _ = ToUint64(0.202, 8)
	expectedBinary = append(expectedBinary, EncodeInt64(amount)...)

	// Nb of byte to encode nb of Token transfers
	expectedBinary = append(expectedBinary, []byte{1}...)

	// Nb of Token transfers
	expectedBinary = append(expectedBinary, []byte{1}...)
	expectedBinary = append(expectedBinary, []byte("0000501fa2db78bcf8ceca129e6139d7e38bf0d61eb905441056b9ebe6f1d1feaf88")...)
	expectedBinary = append(expectedBinary, []byte("0000b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646")...)
	amount, _ = ToUint64(100, 8)
	expectedBinary = append(expectedBinary, EncodeInt64(amount)...)
	expectedBinary = append(expectedBinary, []byte{1}...)
	expectedBinary = append(expectedBinary, []byte{1}...)

	// Recipients
	// Nb of bytes to encode nb
	expectedBinary = append(expectedBinary, []byte{1}...)
	// Nb of recipients
	expectedBinary = append(expectedBinary, []byte{2}...)
	// recipient #1 (first byte = unnamed)
	expectedBinary = append(expectedBinary, []byte{0}...)
	expectedBinary = append(expectedBinary, []byte("0000501fa2db78bcf8ceca129e6139d7e38bf0d61eb905441056b9ebe6f1d1feaf88")...)
	// recipient #2 (first byte = named)
	expectedBinary = append(expectedBinary, []byte{1}...)
	expectedBinary = append(expectedBinary, []byte("0000501fa2db78bcf8ceca129e6139d7e38bf0d61eb905441056b9ebe6f1d1feaf88")...)
	expectedBinary = append(expectedBinary, []byte("vote_for_class_president")...)
	expectedBinary = append(expectedBinary, []byte("[\"Judy\"]")...)
	// expectedBinary = append(expectedBinary, publicKey...)
	// expectedBinary = append(expectedBinary, EncodeInt32(uint32(len(tx.previousSignature)))...)
	// expectedBinary = append(expectedBinary, tx.previousSignature...)

	if !reflect.DeepEqual(payload, expectedBinary) {
		t.Errorf("expected payload %v, got %v", expectedBinary, payload)
	}

}

func TestSetPreviousSignatureAndPreviousPublicKey(t *testing.T) {
	examplePublicKey := []byte("0101044d91a0a1a7cf06a2902d3842f82d2791bcbf3ee6f6dc8de0f90e53e9991c3cb33684b7b9e66f26e7c9f5302f73c69897be5f301de9a63521a08ac4ef34c18728")
	exampleSignature := []byte("3044022009ed5124c35feb3449f4287eb5a885dec06f10491146bf73d44684f5a2ced8d7022049e1fb29fcd6e622a8cd2e120931ab038987edbdc44e7a9ec12e5a290599a97e")

	tx := NewTransaction(TransferType)
	tx.SetPreviousSignatureAndPreviousPublicKey(exampleSignature, examplePublicKey)

	if !reflect.DeepEqual(tx.PreviousPublicKey, examplePublicKey) {
		t.Errorf("expected previousPublicKey %v, got %v", examplePublicKey, tx.PreviousPublicKey)
	}
	if !reflect.DeepEqual(tx.PreviousSignature, exampleSignature) {
		t.Errorf("expected PreviousSignature %v, got %v", exampleSignature, tx.PreviousSignature)
	}
}

func TestSetAddress(t *testing.T) {
	exampleAddress := []byte("0000501fa2db78bcf8ceca129e6139d7e38bf0d61eb905441056b9ebe6f1d1feaf88")

	tx := NewTransaction(TransferType)
	tx.SetAddress(exampleAddress)

	if !reflect.DeepEqual(tx.Address, exampleAddress) {
		t.Errorf("expected previousPublicKey %v, got %v", exampleAddress, tx.Address)
	}
}

func TestBuild(t *testing.T) {

	tx := TransactionBuilder{TxType: TransferType}

	ucoAddress, _ := hex.DecodeString("00001ff1733caa91336976ee7cef5aff6bb26c7682213b8e6770ab82272f966dac35")

	amount, _ := ToUint64(10.0, 8)
	tx.AddUcoTransfer(
		ucoAddress,
		amount,
	)
	tx.Build([]byte("seed"), 0, ED25519, SHA256)

	expectedAddress, _ := hex.DecodeString("00001ff1733caa91336976ee7cef5aff6bb26c7682213b8e6770ab82272f966dac35")
	expectedPreviousPublicKey, _ := hex.DecodeString("000161d6cd8da68207bd01198909c139c130a3df3a8bd20f4bacb123c46354ccd52c")

	if !reflect.DeepEqual(tx.Address, expectedAddress) {
		t.Errorf("expected address %v, got %v", expectedAddress, tx.Address)
	}

	if !reflect.DeepEqual(tx.PreviousPublicKey, expectedPreviousPublicKey) {
		t.Errorf("expected previousPublicKey %v, got %v", expectedPreviousPublicKey, tx.PreviousPublicKey)
	}

	test, _ := Verify(tx.PreviousSignature, tx.previousSignaturePayload(), tx.PreviousPublicKey)
	if !test {
		t.Errorf("Error when verifying the previous signature")
	}
}

func TestOriginSignaturePayload(t *testing.T) {
	code := `
	condition inherit: [
		uco_transferred: 0.020
	  ]

	  actions triggered by: transaction do
		  set_type transfer
		  add_uco_ledger to: "000056E763190B28B4CF9AAF3324CF379F27DE9EF7850209FB59AA002D71BA09788A", amount: 0.020
	  end
    `
	content := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec sit amet leo egestas, lobortis lectus a, dignissim orci.")
	secret := []byte("mysecret")
	seed := []byte("seed")

	tx := NewTransaction(TransferType)
	tx.AddOwnership(
		secret,
		[]AuthorizedKey{
			{
				PublicKey:          []byte("0001b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646"),
				EncryptedSecretKey: []byte("00501fa2db78bcf8ceca129e6139d7e38bf0d61eb905441056b9ebe6f1d1feaf88"),
			},
			{
				PublicKey:          []byte("0001a1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646"),
				EncryptedSecretKey: []byte("00501fa2db78bcf8ceca129e6139d7e38bf0d61eb905441056b9ebe6f1d1feaf88"),
			},
		},
	)

	amount, _ := ToUint64(0.202, 8)
	amount2, _ := ToUint64(100, 8)
	tx.AddUcoTransfer(
		[]byte("0000b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646"),
		amount)
	tx.AddTokenTransfer(
		[]byte("0000b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646"),
		[]byte("0000501fa2db78bcf8ceca129e6139d7e38bf0d61eb905441056b9ebe6f1d1feaf88"),
		amount2,
		1)
	tx.SetCode(code)
	tx.SetContent(content)
	tx.AddRecipient(
		[]byte("0000501fa2db78bcf8ceca129e6139d7e38bf0d61eb905441056b9ebe6f1d1feaf88"))

	tx.Build(seed, 0, P256, SHA256)

	payload := tx.OriginSignaturePayload()

	publicKey, privateKey, _ := DeriveKeypair([]byte(seed), 0, P256)
	Sign(privateKey, tx.PreviousPublicKey)

	expectedBinary := make([]byte, 0)
	// Version
	expectedBinary = append(expectedBinary, EncodeInt32(2)...)
	expectedBinary = append(expectedBinary, tx.Address...)
	expectedBinary = append(expectedBinary, []byte{253}...)

	// Code size
	expectedBinary = append(expectedBinary, EncodeInt32(uint32(len(code)))...)
	expectedBinary = append(expectedBinary, []byte(code)...)

	// Content size
	expectedBinary = append(expectedBinary, EncodeInt32(uint32(len(content)))...)
	expectedBinary = append(expectedBinary, []byte(content)...)

	// Nb of byte to encode nb of ownerships
	expectedBinary = append(expectedBinary, []byte{1}...)

	// Nb ownerships
	expectedBinary = append(expectedBinary, []byte{1}...)

	// Secret size
	expectedBinary = append(expectedBinary, EncodeInt32(uint32(len(secret)))...)
	expectedBinary = append(expectedBinary, []byte(secret)...)

	// Nb of byte to encode nb of authorized key
	expectedBinary = append(expectedBinary, []byte{1}...)

	// Nb of authorized keys
	expectedBinary = append(expectedBinary, []byte{2}...)

	// Authorized keys encoding
	expectedBinary = append(expectedBinary, []byte("0001b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646")...)
	expectedBinary = append(expectedBinary, []byte("00501fa2db78bcf8ceca129e6139d7e38bf0d61eb905441056b9ebe6f1d1feaf88")...)
	expectedBinary = append(expectedBinary, []byte("0001a1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646")...)
	expectedBinary = append(expectedBinary, []byte("00501fa2db78bcf8ceca129e6139d7e38bf0d61eb905441056b9ebe6f1d1feaf88")...)

	// Nb of byte to encode nb of uco transfers
	expectedBinary = append(expectedBinary, []byte{1}...)

	// Nb of uco transfers
	expectedBinary = append(expectedBinary, []byte{1}...)
	expectedBinary = append(expectedBinary, []byte("0000b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646")...)
	amount, _ = ToUint64(0.202, 8)
	expectedBinary = append(expectedBinary, EncodeInt64(amount)...)

	// Nb of byte to encode nb of Token transfers
	expectedBinary = append(expectedBinary, []byte{1}...)

	// Nb of Token transfers
	expectedBinary = append(expectedBinary, []byte{1}...)
	expectedBinary = append(expectedBinary, []byte("0000501fa2db78bcf8ceca129e6139d7e38bf0d61eb905441056b9ebe6f1d1feaf88")...)
	expectedBinary = append(expectedBinary, []byte("0000b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646")...)
	amount, _ = ToUint64(100, 8)
	expectedBinary = append(expectedBinary, EncodeInt64(amount)...)
	expectedBinary = append(expectedBinary, []byte{1}...)
	expectedBinary = append(expectedBinary, []byte{1}...)

	// Recipients
	// Nb of bytes to encode nb
	expectedBinary = append(expectedBinary, []byte{1}...)
	// Nb of recipients
	expectedBinary = append(expectedBinary, []byte{1}...)
	// recipient #1 (first byte = unnamed)
	expectedBinary = append(expectedBinary, []byte{0}...)
	expectedBinary = append(expectedBinary, []byte("0000501fa2db78bcf8ceca129e6139d7e38bf0d61eb905441056b9ebe6f1d1feaf88")...)

	expectedBinary = append(expectedBinary, publicKey...)
	expectedBinary = append(expectedBinary, byte(len(tx.PreviousSignature)))
	expectedBinary = append(expectedBinary, tx.PreviousSignature...)
	if !reflect.DeepEqual(payload, expectedBinary) {
		t.Errorf("expected payload %v, got %v", expectedBinary, payload)
	}

}

func TestOriginSign(t *testing.T) {

	originPublicKey, originPrivateKey, _ := DeriveKeypair([]byte("origin_seed"), 0, P256)

	tx := NewTransaction(TransferType)
	tx.Build([]byte("seed"), 0, P256, SHA256)
	tx.OriginSign(originPrivateKey)

	test, err := Verify(tx.OriginSignature, tx.OriginSignaturePayload(), originPublicKey)
	if !test {
		t.Errorf("Can't verify OriginSign %s", err)
	}
}

func TestToJSONMap(t *testing.T) {
	addressHex := "00002223bbd4ec3d64ae597696c7d7ade1cee65c639d885450ad2d7b75592ac76afa"
	address, _ := hex.DecodeString(addressHex)
	code := "@version 1\ncondition inherit: []"
	content := "hello"
	contentHex := "68656c6c6f"

	// prepare
	tx := NewTransaction(DataType)
	tx.SetAddress([]byte(address))
	tx.SetCode(code)
	tx.SetContent([]byte(content))
	tx.AddRecipient(address)
	tx.AddRecipientForNamedAction(address, []byte("vote_for_class_president"), []byte("[\"Rudy\"]"))
	tx.AddTokenTransfer(address, address, 33, 65)
	tx.AddUcoTransfer(address, 64)

	// run
	jsonMap, err := tx.ToJSONMap()
	if err != nil {
		t.Errorf("ToJSONMap() errored: %s", err)
		return
	}

	// asserts
	if jsonMap["address"] != addressHex {
		t.Error("Unexpected address")
	}

	data := jsonMap["data"].(map[string]interface{})
	if data["code"] != code {
		t.Error("Unexpected code")
	}
	if data["content"] != contentHex {
		t.Error("Unexpected content")
	}

	recipients := data["recipients"].([]map[string]interface{})
	recipient1 := recipients[0]
	recipient2 := recipients[1]
	recipient2Args := recipient2["args"].([]interface{})

	if recipient1["address"] != addressHex {
		t.Error("Unexpected recipient1 address")
	}
	if recipient1["action"] != nil {
		t.Error("Unexpected recipient1 action")
	}
	if recipient1["args"] != nil {
		t.Error("Unexpected recipient1 args")
	}

	if recipient2["address"] != addressHex {
		t.Error("Unexpected recipient2 address")
	}
	if recipient2["action"] != "vote_for_class_president" {
		t.Error("Unexpected recipient2 action")
	}
	if len(recipient2Args) != 1 {
		t.Error("Unexpected recipient2 args length")
	}
	if recipient2Args[0] != "Rudy" {
		t.Error("Unexpected recipient2 args 1")
	}

	ledger := data["ledger"].(map[string]interface{})
	ucoTransfers := ledger["uco"].(map[string]interface{})["transfers"]
	ucoTransfer1 := ucoTransfers.([]map[string]interface{})[0]
	if ucoTransfer1["amount"] != uint64(64) {
		t.Error("Unexpected uco transfer 1 amount")
	}
	if ucoTransfer1["to"] != addressHex {
		t.Error("Unexpected uco transfer 1 to")
	}

	tokenTransfers := ledger["token"].(map[string]interface{})["transfers"]
	tokenTransfer1 := tokenTransfers.([]map[string]interface{})[0]
	if tokenTransfer1["amount"] != uint64(33) {
		t.Error("Unexpected token transfer 1 amount")
	}
	if tokenTransfer1["to"] != addressHex {
		t.Error("Unexpected token transfer 1 to")
	}
	if tokenTransfer1["tokenAddress"] != addressHex {
		t.Error("Unexpected token transfer 1 tokenAddress")
	}
	if tokenTransfer1["tokenId"] != 65 {
		t.Error("Unexpected token transfer 1 tokenId")
	}
}
