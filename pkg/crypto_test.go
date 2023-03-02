package archethic

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"log"
	"reflect"
	"testing"
)

func TestHash(t *testing.T) {
	myFakeData := []byte("myfakedata")
	tests := []struct {
		input    []byte
		algo     HashAlgo
		expected string
	}{
		{input: myFakeData, algo: SHA256, expected: "004e89e81096eb09c74a29bdf66e41fc118b6d17ac547223ca6629a71724e69f23"},
		{input: myFakeData, algo: SHA512, expected: "01c09b378f954c39f8e3c2cc4ed9108937c6e6dbfa9f754a344bd395d2ba55aba9f071987a2c014f9c54d47931b243088aa2dd6c6d90ec92a67f8a9dfdd83eba58"},
		{input: myFakeData, algo: SHA3_256, expected: "029ddb36eabafb047ad869b9e4d35e2c5e6893b6bd2d1cdbdaec13425779f0f9da"},
		{input: myFakeData, algo: SHA3_512, expected: "03f64fe5d472619d235212f843c1ed8ae43598c3a5973eead66d70f88f147a0aaabcbcdc6aed160b0ae5cdf5d48871602827b242c479f999647c377698cb8b7d4f"},
		{input: myFakeData, algo: BLAKE2B, expected: "04f4101890104371a4d673ed717e824c80634edf3cb39e3eeff555049c0a025e5f13a6aa938c7501a98471cad9c13870c13e8691e97229e4a4b4e1930221c02ab8"},
	}

	for _, test := range tests {
		output := Hash(test.input, test.algo)
		outputHex := hex.EncodeToString(output)
		if outputHex != test.expected {
			t.Errorf("Hash(%q, %q) = %q, expected %q", test.input, test.algo, output, test.expected)
		}
	}
}

func TestDeriveKeyPair(t *testing.T) {
	seed := []byte("seed")
	index := uint32(0)
	tests := []struct {
		seed     []byte
		index    uint32
		curve    Curve
		expected string
	}{
		{seed: seed, index: index, curve: ED25519, expected: "000161d6cd8da68207bd01198909c139c130a3df3a8bd20f4bacb123c46354ccd52c"},
		{seed: seed, index: index, curve: P256, expected: "0101044d91a0a1a7cf06a2902d3842f82d2791bcbf3ee6f6dc8de0f90e53e9991c3cb33684b7b9e66f26e7c9f5302f73c69897be5f301de9a63521a08ac4ef34c18728"},
		{seed: seed, index: index, curve: SECP256K1, expected: "0201044d02d071e7e24348fc24951bded20c08409b075c7956348fef89e118370f382cf99c064b17ad950aaeb1ae04971afdc6a44d68e731b8d0a01a8f56eade92875a"},
	}

	for i, test := range tests {
		publicKey, _ := DeriveKeypair(test.seed, test.index, test.curve)
		publicKeyHex := hex.EncodeToString(publicKey)
		if publicKeyHex != test.expected {
			t.Errorf("Test %d for %d: expected public key %s, but got %s", i, test.curve, test.expected, publicKeyHex)
		}
	}

	keypair1, _ := DeriveKeypair(seed, 0, P256)
	keypair2, _ := DeriveKeypair(seed, 1, P256)

	if reflect.DeepEqual(keypair1, keypair2) {
		t.Error("Expected keypair1 and keypair2 to be different")
	}
}

func TestSignAndVerify(t *testing.T) {
	seed := []byte("seed")
	index := uint32(0)
	message := []byte("hello")
	tests := []struct {
		seed  []byte
		index uint32
		curve Curve
	}{
		{seed: seed, index: index, curve: ED25519},
		{seed: seed, index: index, curve: P256},
		{seed: seed, index: index, curve: SECP256K1},
	}

	for _, test := range tests {
		publicKey, privateKey := DeriveKeypair(test.seed, test.index, test.curve)
		sig := Sign(privateKey, message)
		result, err := Verify(sig, message, publicKey)
		if err != nil {
			log.Println(err)
		}
		if !result {
			t.Errorf("%d signature verification failed", test.curve)
		}
	}
}

func TestEcEncrypt(t *testing.T) {
	textToEncrypt := []byte("hello")
	publicKey, privateKey := DeriveKeypair([]byte("seed"), 0, P256)
	cipherText := EcEncrypt(textToEncrypt, publicKey)
	result := EcDecrypt(cipherText, privateKey)
	if string(textToEncrypt) != string(result) {
		t.Errorf("Ec encrypt / decrypt failed for P256")
	}

	publicKey, privateKey = DeriveKeypair([]byte("seed"), 0, ED25519)
	cipherText = EcEncrypt(textToEncrypt, publicKey)
	result = EcDecrypt(cipherText, privateKey)
	if string(textToEncrypt) != string(result) {
		t.Errorf("Ec encrypt / decrypt failed for ED25519")
	}

	publicKey, privateKey = DeriveKeypair([]byte("seed"), 0, SECP256K1)
	cipherText = EcEncrypt(textToEncrypt, publicKey)
	result = EcDecrypt(cipherText, privateKey)
	if string(textToEncrypt) != string(result) {
		t.Errorf("Ec encrypt / decrypt failed for SECP256K1")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	data := []byte("hello")

	encrypted := AesEncrypt(data, key)

	decrypted := AesDecrypt(encrypted, key)

	if !bytes.Equal(decrypted, data) {
		t.Errorf("Decrypted data does not match original data")
	}
}
