package archethic

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
)

func NewKeychainTransaction(seed []byte, authorizedPublicKeys [][]byte) TransactionBuilder {
	keychain := NewKeychain(seed)
	keychain.AddService("uco", "m/650'/0/0", ED25519, SHA256)

	aesKey := make([]byte, 32)
	rand.Read(aesKey)

	authorizedKeys := make([]AuthorizedKey, len(authorizedPublicKeys))
	for i, key := range authorizedPublicKeys {
		authorizedKeys[i] = AuthorizedKey{
			publicKey:          key,
			encryptedSecretKey: EcEncrypt(aesKey, key),
		}
	}

	tx := TransactionBuilder{}
	tx.SetType(KeychainType)
	tx.SetContent(keychain.ToDID().ToJSON())
	tx.AddOwnership(AesEncrypt(keychain.toBytes(), aesKey), authorizedKeys)
	tx.Build(seed, 0, ED25519, SHA256)
	return tx
}

func NewAccessTransaction(seed []byte, keychainAddress []byte) TransactionBuilder {
	aesKey := make([]byte, 32)
	rand.Read(aesKey)

	publicKey, _ := DeriveKeypair(seed, 0, ED25519)
	encryptedSecretKey := EcEncrypt(aesKey, publicKey)

	authorizedKeys := []AuthorizedKey{
		{
			publicKey:          publicKey,
			encryptedSecretKey: encryptedSecretKey,
		},
	}

	tx := TransactionBuilder{}
	tx.SetType(KeychainAccessType)
	tx.AddOwnership(AesEncrypt(keychainAddress, aesKey), authorizedKeys)
	tx.Build(seed, 0, ED25519, SHA256)
	return tx
}

func GetKeychain(seed []byte, client APIClient) *Keychain {
	publicKey, privateKey := DeriveKeypair(seed, 0, ED25519)
	accessKeychainAddress := DeriveAddress(seed, 1, ED25519, SHA256)
	accessOwnerships := client.GetTransactionOwnerships(hex.EncodeToString(accessKeychainAddress))
	if len(accessOwnerships) == 0 {
		panic("Keychain doesn't exist")
	}
	accessSecret := accessOwnerships[0].Secret
	accessAuthorizedKeys := accessOwnerships[0].AuthorizedPublicKeys

	var accessSecretKey []byte
	for _, authKey := range accessAuthorizedKeys {
		if bytes.Equal(authKey.PublicKey, publicKey) {
			accessSecretKey = authKey.EncryptedSecretKey
		}
	}

	accessKey := EcDecrypt(accessSecretKey, privateKey)
	keychainAddress := AesDecrypt(accessSecret, accessKey)

	keychainOwnerships := client.GetLastTransactionOwnerships(hex.EncodeToString(keychainAddress))

	keychainSecret := keychainOwnerships[0].Secret
	keychainAuthorizedKeys := keychainOwnerships[0].AuthorizedPublicKeys

	var keychainSecretKey []byte
	for _, authKey := range keychainAuthorizedKeys {
		if bytes.Equal(authKey.PublicKey, publicKey) {
			keychainSecretKey = authKey.EncryptedSecretKey
		}
	}
	keychainKey := EcDecrypt(keychainSecretKey, privateKey)
	return DecodeKeychain(AesDecrypt(keychainSecret, keychainKey))
}
