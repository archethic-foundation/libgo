package archethic

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"
)

func TestKeychainToDID(t *testing.T) {
	seed := []byte("abcdefghijklmnopqrstuvwxyz")
	keychain := NewKeychain(seed)
	publicKey, _ := keychain.DeriveKeypair("uco", 0)
	address := DeriveAddress(seed, 0, keychain.services["uco"].curve, keychain.services["uco"].hashAlgo)

	json := keychain.ToDID()
	id := json.id
	verificationMethod := json.verificationMethod

	if id != fmt.Sprintf("did:archethic:%s", hex.EncodeToString(address)) {
		t.Errorf("Unexpected id. Expected did:archethic:%s, got %s", address, id)
	}

	expected := []DIDKeyMaterial{
		{
			id:           fmt.Sprintf("%s#uco", id),
			keyType:      "JsonWebKey2020",
			publicKeyJwk: KeyToJWK(publicKey, "uco"),
		},
	}

	if !reflect.DeepEqual(expected, verificationMethod) {
		t.Errorf("Unexpected verificationMethod. Expected %v, got %v", expected, verificationMethod)
	}
}

func TestKeychainEncode(t *testing.T) {
	seed := []byte("myseed")

	keychain := Keychain{seed: seed, version: 1, services: map[string]Service{
		"uco": {
			derivationPath: "m/650'/0/0",
			curve:          ED25519,
			hashAlgo:       SHA256,
		},
	}}

	buf := make([]byte, 0)
	buf = append(buf, 0, 0, 0, 1)
	buf = append(buf, 6)
	buf = append(buf, []byte("myseed")...)
	buf = append(buf, 1)
	buf = append(buf, 3)
	buf = append(buf, []byte("uco")...)
	buf = append(buf, 10)
	buf = append(buf, []byte("m/650'/0/0")...)
	buf = append(buf, 0)
	buf = append(buf, 0)

	if !reflect.DeepEqual(keychain.toBytes(), buf) {
		t.Errorf("Keychain encoding failed. Expected %v, got %v", buf, keychain.toBytes())
	}
}

func TestDecodeKeychain(t *testing.T) {

	buf := make([]byte, 0)
	buf = append(buf, 0, 0, 0, 1)
	buf = append(buf, 6)
	buf = append(buf, []byte("myseed")...)
	buf = append(buf, 1)
	buf = append(buf, 3)
	buf = append(buf, []byte("uco")...)
	buf = append(buf, 10)
	buf = append(buf, []byte("m/650'/0/0")...)
	buf = append(buf, 0)
	buf = append(buf, 0)

	keychain := DecodeKeychain(buf)

	if !bytes.Equal([]byte("myseed"), keychain.seed) {
		t.Errorf("Expected seed to be %v, got %v", []byte("myseed"), keychain.seed)
	}

	services := map[string]Service{
		"uco": {
			derivationPath: "m/650'/0/0",
			curve:          ED25519,
			hashAlgo:       SHA256,
		},
	}

	if !reflect.DeepEqual(services, keychain.services) {
		t.Errorf("Expected services to be %v, got %v", services, keychain.services)
	}

}

func TestBuildTransaction(t *testing.T) {

	seed := []byte("seed")

	keychain := Keychain{seed: seed, version: 1, services: map[string]Service{
		"uco": {
			derivationPath: "m/650'/0/0",
			curve:          ED25519,
			hashAlgo:       SHA256,
		},
	}}

	tx := TransactionBuilder{txType: TransferType}
	tx.AddUcoTransfer(
		[]byte("0000b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646"),
		toUint64(10.0, 8),
	)

	tx = keychain.BuildTransaction(tx, "uco", 0)

	expectedPreviousPublicKey, _ := keychain.DeriveKeypair("uco", 0)
	expectedAddress := keychain.DeriveAddress("uco", 1)

	if !reflect.DeepEqual(tx.address, expectedAddress) {
		t.Errorf("expected address %v, got %v", expectedAddress, tx.address)
	}

	if !reflect.DeepEqual(tx.previousPublicKey, expectedPreviousPublicKey) {
		t.Errorf("expected previousPublicKey %v, got %v", expectedPreviousPublicKey, tx.previousPublicKey)
	}

	test, err := Verify(tx.previousSignature, tx.previousSignaturePayload(), tx.previousPublicKey)
	if !test {
		t.Errorf("Error when verifying the previous signature")
		t.Error(err)
	}
}
