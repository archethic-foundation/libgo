package archethic

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type Keychain struct {
	Seed     []byte
	Version  uint8
	Services map[string]Service
}

type Service struct {
	DerivationPath string
	Curve          Curve
	HashAlgo       HashAlgo
}

type DID struct {
	Context            []string
	Id                 string
	Authentication     []DIDKeyMaterial
	VerificationMethod []DIDKeyMaterial
}

type DIDKeyMaterial struct {
	Id           string
	KeyType      string
	PublicKeyJwk map[string]string
}

func (s Service) toBytes() []byte {
	buf := make([]byte, 0)
	buf = append(buf, byte(len(s.DerivationPath)))
	buf = append(buf, []byte(s.DerivationPath)...)
	buf = append(buf, byte(s.Curve))
	buf = append(buf, byte(s.HashAlgo))
	return buf
}

// NewKeychain instanciates a new Keychain struct
func NewKeychain(seed []byte) *Keychain {
	return &Keychain{
		Seed:    seed,
		Version: 1,
		Services: map[string]Service{
			"uco": {
				DerivationPath: "m/650'/0/0",
				Curve:          P256,
				HashAlgo:       SHA256,
			},
		},
	}
}

func (k *Keychain) AddService(name string, derivationPath string, curve Curve, hashAlgo HashAlgo) {
	k.Services[name] = Service{
		DerivationPath: derivationPath,
		Curve:          curve,
		HashAlgo:       hashAlgo,
	}
}

func (k Keychain) ToDID() DID {
	address := DeriveAddress(k.Seed, 0, P256, SHA256)
	keyMaterials := make([]DIDKeyMaterial, 0)

	for serviceName, service := range k.Services {
		splittedPath := strings.Split(service.DerivationPath, "/")
		for i := 0; i < len(splittedPath); i++ {
			splittedPath[i] = strings.ReplaceAll(splittedPath[i], "'", "")
			purpose := splittedPath[i]
			if purpose == "650" {
				publicKey, _ := DeriveArchethicKeypair(k.Seed, service.DerivationPath, 0, service.Curve)
				keyMaterials = append(keyMaterials, DIDKeyMaterial{
					Id:           fmt.Sprintf("did:archethic:%x#%s", address, serviceName),
					KeyType:      "JsonWebKey2020",
					PublicKeyJwk: KeyToJWK(publicKey, serviceName),
				})
			}
		}
	}

	return DID{
		Context: []string{
			"https://www.w3.org/ns/did/v1",
		},
		Id:                 fmt.Sprintf("did:archethic:%x", address),
		Authentication:     keyMaterials,
		VerificationMethod: keyMaterials,
	}
}

func (d DID) ToJSON() []byte {
	json, _ := json.Marshal(d)
	return json
}

func KeyToJWK(publicKey []byte, keyId string) map[string]string {
	curveID := publicKey[0]
	keyBytes := publicKey[2:]
	switch Curve(curveID) {
	case ED25519:
		key := ed25519.PublicKey(keyBytes)
		return map[string]string{
			"kty": "OKP",
			"crv": "Ed25519",
			"x":   pointToBase64Url(key),
			"kid": keyId,
		}
	case P256:

		curve := elliptic.P256()
		pubKeyX, pubKeyY := elliptic.Unmarshal(curve, keyBytes)
		if pubKeyX == nil || pubKeyY == nil {
			panic("can't unmarshall public key")
		}
		publicKey := ecdsa.PublicKey{Curve: curve, X: pubKeyX, Y: pubKeyY}

		return map[string]string{
			"kty": "EC",
			"crv": "P256",
			"x":   pointToBase64Url(publicKey.X.Bytes()),
			"y":   pointToBase64Url(publicKey.Y.Bytes()),
			"kid": keyId,
		}
	default:
		panic("Unsupported elliptic curve")
	}
}

func pointToBase64Url(p []byte) string {
	buf := base64.StdEncoding.EncodeToString(p)

	r1 := regexp.MustCompile(`/\+/g`)
	r2 := regexp.MustCompile(`/\//g`)
	r3 := regexp.MustCompile(`/=+$/g`)

	buf = r1.ReplaceAllString(buf, "_")
	buf = r2.ReplaceAllString(buf, "_")
	buf = r3.ReplaceAllString(buf, "")

	return buf
}

func (k Keychain) toBytes() []byte {
	buf := make([]byte, 0)

	version := make([]byte, 4)
	binary.BigEndian.PutUint32(version, uint32(k.Version))
	buf = append(buf, version...)

	buf = append(buf, byte(len(k.Seed)))
	buf = append(buf, k.Seed...)
	buf = append(buf, byte(len(k.Services)))

	for name, service := range k.Services {
		buf = append(buf, byte(len(name)))
		buf = append(buf, []byte(name)...)
		buf = append(buf, service.toBytes()...)
	}

	return buf
}

func (k Keychain) DeriveKeypair(serviceName string, index uint8) ([]byte, []byte) {
	service, ok := k.Services[serviceName]

	if !ok {
		panic("Service doesn't exists in the keychain")
	}

	return DeriveArchethicKeypair(k.Seed, service.DerivationPath, index, service.Curve)
}

func DeriveArchethicKeypair(seed []byte, derivationPath string, index uint8, curve Curve) ([]byte, []byte) {
	indexedPath := replaceDerivationPathIndex(derivationPath, index)
	h := sha256.New()
	h.Write([]byte(indexedPath))
	hashedPath := h.Sum(nil)

	hm := hmac.New(sha512.New, seed)
	hm.Write(hashedPath)
	extendedSeed := hm.Sum(nil)
	extendedSeed = extendedSeed[:32]
	return GenerateDeterministicKeypair(extendedSeed, curve, KEYCHAIN_ORIGIN_ID)
}

func replaceDerivationPathIndex(derivationPath string, index uint8) string {
	splitted := strings.Split(derivationPath, "/")
	splitted = splitted[:len(splitted)-1]
	splitted = append(splitted, strconv.Itoa(int(index)))
	return strings.Join(splitted[:], "/")
}

func DecodeKeychain(binaryInput []byte) *Keychain {
	byteReader := bufio.NewReader(bytes.NewReader(binaryInput))
	version := make([]byte, 4)
	byteReader.Read(version)
	versionInt := uint8(version[3])

	seedSize, _ := byteReader.ReadByte()
	seed := make([]byte, seedSize)
	byteReader.Read(seed)
	nbServices, _ := byteReader.ReadByte()

	k := &Keychain{
		Seed:     seed,
		Version:  versionInt,
		Services: make(map[string]Service),
	}

	for i := 0; i < int(nbServices); i++ {
		serviceNameLength, _ := byteReader.ReadByte()
		serviceName := make([]byte, serviceNameLength)
		byteReader.Read(serviceName)
		derivationPathLength, _ := byteReader.ReadByte()
		derivationPath := make([]byte, derivationPathLength)
		byteReader.Read(derivationPath)
		curveID, _ := byteReader.ReadByte()
		hashAlgoID, _ := byteReader.ReadByte()

		k.AddService(string(serviceName), string(derivationPath), Curve(curveID), HashAlgo(hashAlgoID))
	}

	return k
}

func (k Keychain) DeriveAddress(serviceName string, index uint8) []byte {
	service, ok := k.Services[serviceName]

	if !ok {
		panic("Service doesn't exists in the keychain")
	}
	publicKey, _ := DeriveArchethicKeypair(k.Seed, service.DerivationPath, index, service.Curve)

	hashedPublicKey := Hash(publicKey, service.HashAlgo)
	result := make([]byte, 0)
	result = append(result, byte(service.Curve))
	result = append(result, hashedPublicKey...)
	return result

}

func (k Keychain) BuildTransaction(transaction TransactionBuilder, serviceName string, index uint8) TransactionBuilder {
	pubKey, privKey := k.DeriveKeypair(serviceName, index)
	address := k.DeriveAddress(serviceName, index+1)
	transaction.SetAddress(address)

	payloadForPreviousSignature := transaction.previousSignaturePayload()
	previousSignature := Sign(privKey, payloadForPreviousSignature)

	transaction.SetPreviousSignatureAndPreviousPublicKey(previousSignature, pubKey)

	return transaction
}
