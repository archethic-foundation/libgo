package archethic

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/aead/ecdh"
	"github.com/agl/ed25519/extra25519"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/decred/dcrd/dcrec/secp256k1"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/sha3"
)

type HashAlgo uint8
type Curve uint8

const (
	SHA256   HashAlgo = 0
	SHA512   HashAlgo = 1
	SHA3_256 HashAlgo = 2
	SHA3_512 HashAlgo = 3
	BLAKE2B  HashAlgo = 4
)

const (
	ED25519   Curve = 0
	P256      Curve = 1
	SECP256K1 Curve = 2
)

type OriginID uint8

const (
	KEYCHAIN_ORIGIN_ID OriginID = 0
	SOFTWARE_ORIGIN_ID OriginID = 1
)

func Add(a, b int) int {
	return a + b
}

// Hash create a hash digest from the data with an hash algorithm identification prepending the digest
func Hash(content []byte, hashAlgo HashAlgo) ([]byte, error) {
	digest, err := hash(content, hashAlgo)
	if err != nil {
		return nil, err
	}
	return append([]byte{byte(hashAlgo)}, digest...), nil
}

func hash(content []byte, hashAlgo HashAlgo) ([]byte, error) {
	switch hashAlgo {
	case SHA256:
		h := sha256.New()
		h.Write(content)
		return h.Sum(nil), nil
	case SHA512:
		h := sha512.New()
		h.Write(content)
		return h.Sum(nil), nil
	case SHA3_256:
		h := sha3.New256()
		h.Write(content)
		return h.Sum(nil), nil
	case SHA3_512:
		h := sha3.New512()
		h.Write(content)
		return h.Sum(nil), nil
	case BLAKE2B:
		h, _ := blake2b.New(64, nil)
		h.Write(content)
		return h.Sum(nil), nil
	default:
		return nil, errors.New("unsupported hash algorithm")
	}
}

// DeriveKeypair generate a keypair using a derivation function with a seed and an index. Each keys is prepending with a curve identification.
func DeriveKeypair(seed []byte, index uint32, curve Curve) ([]byte, []byte, error) {
	pvKey := derivePrivateKey(seed, index)
	return GenerateDeterministicKeypair(pvKey, curve, SOFTWARE_ORIGIN_ID)
}

func derivePrivateKey(seed []byte, index uint32) []byte {

	// Derive master keys
	hash := sha512.Sum512(seed)
	masterKey := hash[:32]
	masterEntropy := hash[32:64]

	// Derive the final seed
	indexBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(indexBuf, uint32(index))
	var extendedSeed []byte
	extendedSeed = append(extendedSeed, masterKey...)
	extendedSeed = append(extendedSeed, indexBuf...)

	mac := hmac.New(sha512.New, masterEntropy)
	mac.Write(extendedSeed)
	hmac := mac.Sum(nil)

	// The first 32 bytes become the next private key
	return hmac[:32]
}

// GenerateDeterministicKeypair generate a new keypair deterministically with a given private key, curve and origin id
func GenerateDeterministicKeypair(pvKey []byte, curve Curve, originID OriginID) ([]byte, []byte, error) {
	pubKey, err := getKeypair(pvKey, curve)
	if err != nil {
		return nil, nil, err
	}
	keyMetadata := []byte{byte(curve), byte(originID)}

	// ED25519 private keys are 64 bytes long (the public key is appended at the end)
	if curve == ED25519 {
		privateKey := append(keyMetadata, pvKey...)
		privateKey = append(privateKey, pubKey...)
		return append(keyMetadata, pubKey...), privateKey, nil
	}
	return append(keyMetadata, pubKey...), append(keyMetadata, pvKey...), nil
}

func getKeypair(privateKey []byte, curve Curve) ([]byte, error) {
	switch curve {
	case P256:
		curve := elliptic.P256()
		key := new(ecdsa.PrivateKey)
		key.D = new(big.Int).SetBytes(privateKey)
		key.PublicKey.Curve = curve
		key.PublicKey.X, key.PublicKey.Y = curve.ScalarBaseMult(privateKey)
		result := elliptic.Marshal(curve, key.X, key.Y)
		return result, nil
	case ED25519:
		_, x, y, err := edwards.GenerateKey(bytes.NewReader(privateKey))
		if err != nil {
			return nil, err
		}
		pub := edwards.NewPublicKey(x, y)
		return pub.Serialize(), nil
	case SECP256K1:
		key, _ := secp256k1.PrivKeyFromBytes(privateKey)
		return key.PubKey().SerializeUncompressed(), nil
	default:
		return nil, errors.New("unsupported elliptic curve")
	}
}

func DeriveAddress(seed []byte, index uint32, curve Curve, hashAlgo HashAlgo) ([]byte, error) {
	publicKey, _, err := DeriveKeypair(seed, index, curve)
	if err != nil {
		return nil, err
	}
	hashedPublicKey, err := Hash(publicKey, hashAlgo)
	if err != nil {
		return nil, err
	}
	return append([]byte{byte(curve)}, hashedPublicKey...), nil
}

func Sign(privateKey []byte, data []byte) ([]byte, error) {

	byteReader := bytes.NewReader(privateKey)
	curve, _ := byteReader.ReadByte()
	byteReader.ReadByte()

	pvKeyBytes := make([]byte, byteReader.Len())
	byteReader.Read(pvKeyBytes)

	switch Curve(curve) {
	case ED25519:
		return ed25519.Sign(pvKeyBytes, data), nil
	case P256:
		sha256Hash := sha256.Sum256(data)
		curve := elliptic.P256()
		key := new(ecdsa.PrivateKey)
		key.D = new(big.Int).SetBytes(pvKeyBytes)
		key.PublicKey.Curve = curve

		key.PublicKey.X, key.PublicKey.Y = curve.ScalarBaseMult(pvKeyBytes)

		sig, err := ecdsa.SignASN1(rand.Reader, key, sha256Hash[:])
		if err != nil {
			return nil, err
		}
		return sig, nil
	case SECP256K1:
		sha256Hash := sha256.Sum256(data)
		privKey, _ := secp256k1.PrivKeyFromBytes(pvKeyBytes)
		sig, err := privKey.Sign(sha256Hash[:])
		if err != nil {
			return nil, err
		}
		return sig.Serialize(), nil
	default:
		return nil, errors.New("unsupported elliptic curve")
	}
}

func Verify(sig []byte, data []byte, publicKey []byte) (bool, error) {

	curveByte := publicKey[:1]
	pubByte := publicKey[2:]
	switch Curve(curveByte[0]) {
	case ED25519:
		key := ed25519.PublicKey(pubByte)
		return ed25519.Verify(key, data, sig), nil
	case P256:
		sha256Hash := sha256.Sum256(data)
		curve := elliptic.P256()
		pubKeyX, pubKeyY := elliptic.Unmarshal(curve, pubByte)
		if pubKeyX == nil || pubKeyY == nil {
			return false, errors.New("can't unmarshall public key")
		}
		publicKey := ecdsa.PublicKey{Curve: curve, X: pubKeyX, Y: pubKeyY}

		return ecdsa.VerifyASN1(&publicKey, sha256Hash[:], sig), nil
	case SECP256K1:
		sha256Hash := sha256.Sum256(data)
		signature, err := secp256k1.ParseDERSignature(sig)
		if err != nil {
			return false, err
		}
		pubKey, err := secp256k1.ParsePubKey(pubByte)
		if err != nil {
			return false, err
		}

		return signature.Verify(sha256Hash[:], pubKey), nil
	default:
		return false, errors.New("curve not supported")
	}
}

func EcEncrypt(data []byte, publicKey []byte) ([]byte, error) {

	byteReader := bytes.NewReader(publicKey)
	curve, _ := byteReader.ReadByte()
	byteReader.ReadByte()

	puKeyBytes := make([]byte, byteReader.Len())
	byteReader.Read(puKeyBytes)

	switch Curve(curve) {
	case ED25519:
		tempPublicKey, tempPrivateKey, err := ed25519.GenerateKey(nil)
		if err != nil {
			return nil, err
		}

		publicKey := new([32]byte)
		extra25519.PublicKeyToCurve25519(publicKey, (*[32]byte)(puKeyBytes))

		tempPublicKey2 := new([32]byte)
		extra25519.PublicKeyToCurve25519(tempPublicKey2, (*[32]byte)(tempPublicKey))

		tempPrivateKey2 := new([32]byte)
		extra25519.PrivateKeyToCurve25519(tempPrivateKey2, (*[64]byte)(tempPrivateKey))

		if err != nil {
			return nil, err
		}

		sharedKey, err := curve25519.X25519(tempPrivateKey2[:], publicKey[:])
		if err != nil {
			return nil, err
		}

		iv, aesKey := deriveSecret(sharedKey[:])
		encrypted, err := aesAuthEncrypt(data, aesKey, iv)
		if err != nil {
			return nil, err
		}

		return append(tempPublicKey2[:], encrypted...), nil
	case P256:

		p256 := ecdh.Generic(elliptic.P256())
		ec := elliptic.P256()
		tempPrivateKey, tempPublicKey, err := p256.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}

		pubKeyX, pubKeyY := elliptic.Unmarshal(ec, puKeyBytes)
		if pubKeyX == nil || pubKeyY == nil {
			return nil, errors.New("can't unmarshall public key")
		}
		publicKey := ecdh.Point{X: pubKeyX, Y: pubKeyY}

		sharedKey := p256.ComputeSecret(tempPrivateKey, publicKey)
		iv, aesKey := deriveSecret(sharedKey)
		encrypted, err := aesAuthEncrypt(data, aesKey, iv)
		if err != nil {
			return nil, err
		}

		ecdsaPublicKey := tempPublicKey.(ecdh.Point)
		result := elliptic.Marshal(ec, ecdsaPublicKey.X, ecdsaPublicKey.Y)
		return append(result, encrypted...), nil
	case SECP256K1:
		tmpPriv, _ := secp256k1.GeneratePrivateKey()

		publicKey, err := secp256k1.ParsePubKey(puKeyBytes)
		if err != nil {
			return nil, err
		}

		sharedKey := secp256k1.GenerateSharedSecret(tmpPriv, publicKey)

		iv, aesKey := deriveSecret(sharedKey)
		encrypted, err := aesAuthEncrypt(data, aesKey, iv)
		if err != nil {
			return nil, err
		}

		return append(tmpPriv.PubKey().SerializeUncompressed(), encrypted...), nil
	default:
		return nil, errors.New("curve not supported")
	}
}

func EcDecrypt(cipherText []byte, privateKey []byte) ([]byte, error) {

	byteReader := bytes.NewReader(privateKey)
	curve, _ := byteReader.ReadByte()
	byteReader.ReadByte()

	pvKeyBytes := make([]byte, byteReader.Len())
	byteReader.Read(pvKeyBytes)

	switch Curve(curve) {
	case ED25519:
		publicKey := cipherText[:32]
		encryptedText := cipherText[32:]

		pvKey := new([32]byte)
		extra25519.PrivateKeyToCurve25519(pvKey, (*[64]byte)(pvKeyBytes))

		sharedKey, err := curve25519.X25519(pvKey[:], publicKey)
		if err != nil {
			return nil, err
		}

		iv, aesKey := deriveSecret(sharedKey)
		return aesAuthDecrypt(encryptedText, aesKey, iv)
	case P256:

		publicKey := cipherText[:65]
		encryptedText := cipherText[65:]
		curve := elliptic.P256()
		key := new(ecdsa.PrivateKey)
		key.D = new(big.Int).SetBytes(pvKeyBytes)
		key.PublicKey.Curve = curve

		key.PublicKey.X, key.PublicKey.Y = curve.ScalarBaseMult(pvKeyBytes)

		p256 := ecdh.Generic(elliptic.P256())

		pubKeyX, pubKeyY := elliptic.Unmarshal(elliptic.P256(), publicKey)
		if pubKeyX == nil || pubKeyY == nil {
			return nil, errors.New("can't unmarshall public key")
		}
		publicKeyPoint := ecdh.Point{X: pubKeyX, Y: pubKeyY}

		sharedKey := p256.ComputeSecret(pvKeyBytes, publicKeyPoint)

		iv, aesKey := deriveSecret(sharedKey)
		return aesAuthDecrypt(encryptedText, aesKey, iv)

	case SECP256K1:
		publicKey := cipherText[:65]
		encryptedText := cipherText[65:]
		pvKey, _ := secp256k1.PrivKeyFromBytes(pvKeyBytes)

		pubKey, _ := secp256k1.ParsePubKey(publicKey)

		sharedKey := secp256k1.GenerateSharedSecret(pvKey, pubKey)

		iv, aesKey := deriveSecret(sharedKey)
		return aesAuthDecrypt(encryptedText, aesKey, iv)
	default:
		return nil, errors.New("curve not supported")
	}
}

func deriveSecret(sharedKey []byte) ([]byte, []byte) {
	h := sha256.New()
	h.Write(sharedKey)
	pseudoRandomKey := h.Sum(nil)

	mac := hmac.New(sha256.New, pseudoRandomKey)
	mac.Write([]byte("0"))
	digest := mac.Sum(nil)
	iv := digest[:32]

	mac = hmac.New(sha256.New, iv)
	mac.Write([]byte("1"))
	digest = mac.Sum(nil)
	aesKey := digest[:32]

	return iv, aesKey
}

func aesAuthEncrypt(data []byte, aesKey []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCMWithNonceSize(block, len(iv))
	if err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nil, iv, data, nil)
	// the AES GCM lib returns the data first then the authentication tag
	// but we want the tag first
	tag := ciphertext[len(ciphertext)-aesgcm.Overhead():]
	ciphertext = append(tag, ciphertext[:len(ciphertext)-aesgcm.Overhead()]...)
	return ciphertext, nil
}

func aesAuthDecrypt(encrypted, aesKey, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	// Create a new GCM cipher with the block.
	gcm, err := cipher.NewGCMWithNonceSize(block, len(iv))
	if err != nil {
		return nil, err
	}

	// the AES GCM lib expects the data first then the authentication tag
	// but we have the tag first
	encrypted = append(encrypted[gcm.Overhead():], encrypted[:gcm.Overhead()]...)
	// Decrypt the message.
	plaintext, err := gcm.Open(nil, iv, encrypted, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func AesEncrypt(data, key []byte) ([]byte, error) {

	iv := make([]byte, 12)
	_, err := rand.Read(iv)
	if err != nil {
		return nil, err
	}

	encrypted, err := aesAuthEncrypt(data, key, iv)
	if err != nil {
		return nil, err
	}
	result := make([]byte, 0)

	result = append(result, iv...)
	return append(result, encrypted...), nil
}

func AesDecrypt(cipherText, key []byte) ([]byte, error) {

	byteReader := bytes.NewReader(cipherText)

	iv := make([]byte, 12)
	byteReader.Read(iv)

	encrypted := make([]byte, byteReader.Len())
	byteReader.Read(encrypted)

	return aesAuthDecrypt(encrypted, key, iv)
}

func EncodeInt32(number uint32) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, number)
	return buf.Bytes()
}

func EncodeInt64(number uint64) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, number)
	return buf.Bytes()
}
