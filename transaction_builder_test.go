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
	tx.AddUcoTransfer(
		[]byte("0000b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646"),
		ToUint64(10.03, 8),
	)

	if len(tx.Data.Ledger.Uco.Transfers) != 1 {
		t.Errorf("expected one transfer, got %d", len(tx.Data.Ledger.Uco.Transfers))
	}

	expectedTo := []byte("0000b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646")
	if !reflect.DeepEqual(tx.Data.Ledger.Uco.Transfers[0].To, expectedTo) {
		t.Errorf("expected to address %v, got %v", expectedTo, tx.Data.Ledger.Uco.Transfers[0].To)
	}

	expectedAmount := ToUint64(10.03, 8)
	if tx.Data.Ledger.Uco.Transfers[0].Amount != expectedAmount {
		t.Errorf("expected amount %d, got %d", expectedAmount, tx.Data.Ledger.Uco.Transfers[0].Amount)
	}
}

func TestAddTokenTransfer(t *testing.T) {

	tx := TransactionBuilder{TxType: TransferType}
	tx.AddTokenTransfer(
		[]byte("0000b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646"),
		[]byte("0000b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646"),
		ToUint64(10.03, 8),
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

	expectedAmount := ToUint64(10.03, 8)
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

	tx.AddUcoTransfer(
		[]byte("0000b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646"),
		ToUint64(0.202, 8))
	tx.AddTokenTransfer(
		[]byte("0000b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646"),
		[]byte("0000501fa2db78bcf8ceca129e6139d7e38bf0d61eb905441056b9ebe6f1d1feaf88"),
		ToUint64(100, 8),
		1)
	tx.SetCode(code)
	tx.SetContent(content)
	tx.AddRecipient(
		[]byte("0000501fa2db78bcf8ceca129e6139d7e38bf0d61eb905441056b9ebe6f1d1feaf88"))

	publicKey, _ := DeriveKeypair([]byte("seed"), 0, ED25519)
	address := DeriveAddress([]byte("seed"), 1, ED25519, SHA256)

	tx.Address = address
	tx.PreviousPublicKey = publicKey

	payload := tx.previousSignaturePayload()

	expectedBinary := make([]byte, 0)
	// Version
	expectedBinary = append(expectedBinary, EncodeInt32(1)...)
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
	expectedBinary = append(expectedBinary, EncodeInt64(ToUint64(0.202, 8))...)

	// Nb of byte to encode nb of Token transfers
	expectedBinary = append(expectedBinary, []byte{1}...)

	// Nb of Token transfers
	expectedBinary = append(expectedBinary, []byte{1}...)
	expectedBinary = append(expectedBinary, []byte("0000501fa2db78bcf8ceca129e6139d7e38bf0d61eb905441056b9ebe6f1d1feaf88")...)
	expectedBinary = append(expectedBinary, []byte("0000b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646")...)
	expectedBinary = append(expectedBinary, EncodeInt64(ToUint64(100, 8))...)
	expectedBinary = append(expectedBinary, []byte{1}...)
	expectedBinary = append(expectedBinary, []byte{1}...)

	// Nb of byte to encode nb of recipients
	expectedBinary = append(expectedBinary, []byte{1}...)
	expectedBinary = append(expectedBinary, []byte{1}...)
	expectedBinary = append(expectedBinary, []byte("0000501fa2db78bcf8ceca129e6139d7e38bf0d61eb905441056b9ebe6f1d1feaf88")...)
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

	tx.AddUcoTransfer(
		ucoAddress,
		ToUint64(10.0, 8),
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

	tx.AddUcoTransfer(
		[]byte("0000b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646"),
		ToUint64(0.202, 8))
	tx.AddTokenTransfer(
		[]byte("0000b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646"),
		[]byte("0000501fa2db78bcf8ceca129e6139d7e38bf0d61eb905441056b9ebe6f1d1feaf88"),
		ToUint64(100, 8),
		1)
	tx.SetCode(code)
	tx.SetContent(content)
	tx.AddRecipient(
		[]byte("0000501fa2db78bcf8ceca129e6139d7e38bf0d61eb905441056b9ebe6f1d1feaf88"))

	tx.Build(seed, 0, P256, SHA256)

	payload := tx.OriginSignaturePayload()

	publicKey, privateKey := DeriveKeypair([]byte(seed), 0, P256)
	Sign(privateKey, tx.PreviousPublicKey)

	expectedBinary := make([]byte, 0)
	// Version
	expectedBinary = append(expectedBinary, EncodeInt32(1)...)
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
	expectedBinary = append(expectedBinary, EncodeInt64(ToUint64(0.202, 8))...)

	// Nb of byte to encode nb of Token transfers
	expectedBinary = append(expectedBinary, []byte{1}...)

	// Nb of Token transfers
	expectedBinary = append(expectedBinary, []byte{1}...)
	expectedBinary = append(expectedBinary, []byte("0000501fa2db78bcf8ceca129e6139d7e38bf0d61eb905441056b9ebe6f1d1feaf88")...)
	expectedBinary = append(expectedBinary, []byte("0000b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646")...)
	expectedBinary = append(expectedBinary, EncodeInt64(ToUint64(100, 8))...)
	expectedBinary = append(expectedBinary, []byte{1}...)
	expectedBinary = append(expectedBinary, []byte{1}...)

	// Nb of byte to encode nb of recipients
	expectedBinary = append(expectedBinary, []byte{1}...)
	expectedBinary = append(expectedBinary, []byte{1}...)
	expectedBinary = append(expectedBinary, []byte("0000501fa2db78bcf8ceca129e6139d7e38bf0d61eb905441056b9ebe6f1d1feaf88")...)
	expectedBinary = append(expectedBinary, publicKey...)
	expectedBinary = append(expectedBinary, byte(len(tx.PreviousSignature)))
	expectedBinary = append(expectedBinary, tx.PreviousSignature...)

	if !reflect.DeepEqual(payload, expectedBinary) {
		t.Errorf("expected payload %v, got %v", expectedBinary, payload)
	}

}

func TestOriginSign(t *testing.T) {

	originPublicKey, originPrivateKey := DeriveKeypair([]byte("origin_seed"), 0, P256)

	tx := NewTransaction(TransferType)
	tx.Build([]byte("seed"), 0, P256, SHA256)
	tx.OriginSign(originPrivateKey)

	test, err := Verify(tx.OriginSignature, tx.OriginSignaturePayload(), originPublicKey)
	if !test {
		t.Errorf("Can't verify OriginSign %s", err)
	}
}

// it("should return a JSON from the transaction", () => {
// 	const originKeypair = deriveKeyPair("origin_seed", 0);
// 	const transactionKeyPair = deriveKeyPair("seed", 0);

// 	const tx = new TransactionBuilder("transfer")
// 	  .addUCOTransfer(
// 		"0000b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646",
// 		toBigInt(0.2193)
// 	  )
// 	  .addOwnership(Uint8Array.from([0, 1, 2, 3, 4]), [
// 		{
// 		  publicKey:
// 			"0001b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646",
// 		  encryptedSecretKey:
// 			"00501fa2db78bcf8ceca129e6139d7e38bf0d61eb905441056b9ebe6f1d1feaf88",
// 		},
// 	  ])
// 	  .build("seed", 0)
// 	  .originSign(originKeypair.privateKey);

// 	const parsedTx = JSON.parse(tx.toJSON());

// 	const previousSig = sign(
// 	  tx.previousSignaturePayload(),
// 	  transactionKeyPair.privateKey
// 	);
// 	const originSig = sign(
// 	  tx.originSignaturePayload(),
// 	  originKeypair.privateKey
// 	);

// 	assert.strictEqual(
// 	  parsedTx.address,
// 	  uint8ArrayToHex(deriveAddress("seed", 1))
// 	);
// 	assert.strictEqual(parsedTx.type, "transfer");
// 	assert.strictEqual(
// 	  parsedTx.previousPublicKey,
// 	  uint8ArrayToHex(transactionKeyPair.publicKey)
// 	);
// 	assert.strictEqual(
// 	  parsedTx.previousSignature,
// 	  uint8ArrayToHex(previousSig)
// 	);
// 	assert.strictEqual(parsedTx.originSignature, uint8ArrayToHex(originSig));
// 	assert.strictEqual(
// 	  parsedTx.data.ownerships[0].secret,
// 	  uint8ArrayToHex(Uint8Array.from([0, 1, 2, 3, 4]))
// 	);
// 	assert.deepStrictEqual(parsedTx.data.ledger.uco.transfers[0], {
// 	  to: "0000b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646",
// 	  amount: toBigInt(0.2193),
// 	});
// 	assert.deepStrictEqual(parsedTx.data.ownerships[0].authorizedKeys, [
// 	  {
// 		publicKey:
// 		  "0001b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646",
// 		encryptedSecretKey:
// 		  "00501fa2db78bcf8ceca129e6139d7e38bf0d61eb905441056b9ebe6f1d1feaf88",
// 	  },
// 	]);
//   });
// });
