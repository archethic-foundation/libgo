package archethic

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
)

func NewKeychainTransaction(seed []byte, authorizedPublicKeys [][]byte) (*TransactionBuilder, error) {
	keychain := NewKeychain(seed)
	keychain.AddService("uco", "m/650'/0/0", ED25519, SHA256)

	aesKey := make([]byte, 32)
	rand.Read(aesKey)

	authorizedKeys := make([]AuthorizedKey, len(authorizedPublicKeys))
	for i, key := range authorizedPublicKeys {
		encryptedSecretKey, err := EcEncrypt(aesKey, key)
		if err != nil {
			return nil, err
		}
		authorizedKeys[i] = AuthorizedKey{
			PublicKey:          key,
			EncryptedSecretKey: encryptedSecretKey,
		}
	}

	tx := NewTransaction(KeychainType)
	keychainToDid, err := keychain.ToDID()
	if err != nil {
		return nil, err
	}
	tx.SetContent(keychainToDid.ToJSON())
	encryptedKeychain, err := AesEncrypt(keychain.toBytes(), aesKey)
	if err != nil {
		return nil, err
	}
	tx.AddOwnership(encryptedKeychain, authorizedKeys)
	tx.Build(seed, 0, ED25519, SHA256)
	return tx, nil
}

func NewKeychainTransactionWithIndex(keychain *Keychain, transactionChainIndex uint32) (*TransactionBuilder, error) {

	aesKey := make([]byte, 32)
	rand.Read(aesKey)

	authorizedKeys := make([]AuthorizedKey, len(keychain.AuthorizedPublicKeys))
	for i, key := range keychain.AuthorizedPublicKeys {
		encryptedSecretKey, err := EcEncrypt(aesKey, key)
		if err != nil {
			return nil, err
		}
		authorizedKeys[i] = AuthorizedKey{
			PublicKey:          key,
			EncryptedSecretKey: encryptedSecretKey,
		}
	}

	tx := NewTransaction(KeychainType)
	keychainToDid, err := keychain.ToDID()
	if err != nil {
		return nil, err
	}
	tx.SetContent(keychainToDid.ToJSON())
	encryptedKeychain, err := AesEncrypt(keychain.toBytes(), aesKey)
	if err != nil {
		return nil, err
	}
	tx.AddOwnership(encryptedKeychain, authorizedKeys)
	tx.Build(keychain.Seed, transactionChainIndex, ED25519, SHA256)
	return tx, nil
}

func NewAccessTransaction(seed []byte, keychainAddress []byte) (*TransactionBuilder, error) {
	aesKey := make([]byte, 32)
	rand.Read(aesKey)

	publicKey, _, err := DeriveKeypair(seed, 0, ED25519)
	if err != nil {
		return nil, err
	}
	encryptedSecretKey, err := EcEncrypt(aesKey, publicKey)
	if err != nil {
		return nil, err
	}

	authorizedKeys := []AuthorizedKey{
		{
			PublicKey:          publicKey,
			EncryptedSecretKey: encryptedSecretKey,
		},
	}

	tx := NewTransaction(KeychainAccessType)
	encryptedKeychainAddress, err := AesEncrypt(keychainAddress, aesKey)
	if err != nil {
		return nil, err
	}
	tx.AddOwnership(encryptedKeychainAddress, authorizedKeys)
	tx.Build(seed, 0, ED25519, SHA256)
	return tx, nil
}

func GetKeychain(seed []byte, client APIClient) (*Keychain, error) {
	publicKey, privateKey, err := DeriveKeypair(seed, 0, ED25519)
	if err != nil {
		return nil, err
	}
	accessKeychainAddress, err := DeriveAddress(seed, 1, ED25519, SHA256)
	if err != nil {
		return nil, err
	}
	accessOwnerships, err := client.GetTransactionOwnerships(hex.EncodeToString(accessKeychainAddress))
	if err != nil {
		return nil, err
	}
	if len(accessOwnerships) == 0 {
		return nil, errors.New("keychain doesn't exist")
	}
	accessSecret := accessOwnerships[0].Secret
	accessAuthorizedKeys := accessOwnerships[0].AuthorizedKeys

	var accessSecretKey []byte
	for _, authKey := range accessAuthorizedKeys {
		if bytes.Equal(authKey.PublicKey, publicKey) {
			accessSecretKey = authKey.EncryptedSecretKey
		}
	}

	accessKey, err := EcDecrypt(accessSecretKey, privateKey)
	if err != nil {
		return nil, err
	}
	keychainAddress, err := AesDecrypt(accessSecret, accessKey)
	if err != nil {
		return nil, err
	}

	keychainOwnerships, err := client.GetLastTransactionOwnerships(hex.EncodeToString(keychainAddress))
	if err != nil {
		return nil, err
	}

	keychainSecret := keychainOwnerships[0].Secret
	keychainAuthorizedKeys := keychainOwnerships[0].AuthorizedKeys

	var keychainSecretKey []byte
	for _, authKey := range keychainAuthorizedKeys {
		if bytes.Equal(authKey.PublicKey, publicKey) {
			keychainSecretKey = authKey.EncryptedSecretKey
		}
	}
	keychainKey, err := EcDecrypt(keychainSecretKey, privateKey)
	if err != nil {
		return nil, err
	}
	encryptedKeychainSecret, err := AesDecrypt(keychainSecret, keychainKey)
	if err != nil {
		return nil, err
	}
	keychain := DecodeKeychain(encryptedKeychainSecret)
	for _, authKey := range keychainAuthorizedKeys {
		keychain.AddAuthorizedPublicKey(authKey.PublicKey)
	}
	return keychain, nil
}
