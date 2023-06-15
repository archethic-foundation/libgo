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
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type Keychain struct {
	Seed                 []byte
	Version              uint8
	Services             map[string]Service
	AuthorizedPublicKeys [][]byte
}

type Service struct {
	DerivationPath string   `json:"derivationPath"`
	Curve          Curve    `json:"curve"`
	HashAlgo       HashAlgo `json:"hashAlgo"`
}

type DID struct {
	Context            []string         `json:"@context"`
	Id                 string           `json:"id"`
	Authentication     []string         `json:"authentication"`
	VerificationMethod []DIDKeyMaterial `json:"verificationMethod"`
}

type DIDKeyMaterial struct {
	Id           string            `json:"id"`
	KeyType      string            `json:"type"`
	PublicKeyJwk map[string]string `json:"publicKeyJwk"`
	Controller   string            `json:"controller"`
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

func (k *Keychain) RemoveService(name string) {
	delete(k.Services, name)
}

func (k *Keychain) AddAuthorizedPublicKey(publicKey []byte) {
	k.AuthorizedPublicKeys = append(k.AuthorizedPublicKeys, publicKey)
}

func (k *Keychain) RemoveAuthorizedPublicKey(publicKey []byte) {
	for i, key := range k.AuthorizedPublicKeys {
		if bytes.Equal(key, publicKey) {
			k.AuthorizedPublicKeys = append(k.AuthorizedPublicKeys[:i], k.AuthorizedPublicKeys[i+1:]...)
			return
		}
	}
}

func (k Keychain) ToDID() (*DID, error) {
	address, err := DeriveAddress(k.Seed, 0, P256, SHA256)
	if err != nil {
		return nil, err
	}

	authentications := make([]string, 0)
	verificationMethods := make([]DIDKeyMaterial, 0)

	for serviceName, service := range k.Services {
		splittedPath := strings.Split(service.DerivationPath, "/")
		for i := 0; i < len(splittedPath); i++ {
			splittedPath[i] = strings.ReplaceAll(splittedPath[i], "'", "")
			purpose := splittedPath[i]
			if purpose == "650" {
				publicKey, _, err := DeriveArchethicKeypair(k.Seed, service.DerivationPath, 0, service.Curve)
				if err != nil {
					return nil, err
				}
				publicKeyJwk, err := KeyToJWK(publicKey, serviceName)
				if err != nil {
					return nil, err
				}
				verificationMethods = append(verificationMethods, DIDKeyMaterial{
					Id:           fmt.Sprintf("did:archethic:%x#%s", address, serviceName),
					KeyType:      "JsonWebKey2020",
					PublicKeyJwk: publicKeyJwk,
					Controller:   fmt.Sprintf("did:archethic:%x", address),
				})
				authentications = append(authentications, fmt.Sprintf("did:archethic:%x#%s", address, serviceName))
			}
		}
	}

	return &DID{
		Context: []string{
			"https://www.w3.org/ns/did/v1",
		},
		Id:                 fmt.Sprintf("did:archethic:%x", address),
		Authentication:     authentications,
		VerificationMethod: verificationMethods,
	}, nil
}

func (d DID) ToJSON() []byte {
	json, _ := json.Marshal(d)
	return json
}

func KeyToJWK(publicKey []byte, keyId string) (map[string]string, error) {
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
		}, nil
	case P256:

		curve := elliptic.P256()
		pubKeyX, pubKeyY := elliptic.Unmarshal(curve, keyBytes)
		if pubKeyX == nil || pubKeyY == nil {
			return nil, errors.New("can't unmarshall public key")
		}
		publicKey := ecdsa.PublicKey{Curve: curve, X: pubKeyX, Y: pubKeyY}

		return map[string]string{
			"kty": "EC",
			"crv": "P256",
			"x":   pointToBase64Url(publicKey.X.Bytes()),
			"y":   pointToBase64Url(publicKey.Y.Bytes()),
			"kid": keyId,
		}, nil
	default:
		return nil, errors.New("unsupported elliptic curve")
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

func (k Keychain) DeriveKeypair(serviceName string, index uint8) ([]byte, []byte, error) {
	service, ok := k.Services[serviceName]

	if !ok {
		return nil, nil, errors.New("service doesn't exists in the keychain")
	}

	return DeriveArchethicKeypair(k.Seed, service.DerivationPath, index, service.Curve)
}

func DeriveArchethicKeypair(seed []byte, derivationPath string, index uint8, curve Curve) ([]byte, []byte, error) {
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

func (k Keychain) DeriveAddress(serviceName string, index uint8) ([]byte, error) {
	service, ok := k.Services[serviceName]

	if !ok {
		return nil, errors.New("service doesn't exists in the keychain")
	}
	publicKey, _, err := DeriveArchethicKeypair(k.Seed, service.DerivationPath, index, service.Curve)
	if err != nil {
		return nil, err
	}

	hashedPublicKey, err := Hash(publicKey, service.HashAlgo)
	if err != nil {
		return nil, err
	}
	result := make([]byte, 0)
	result = append(result, byte(service.Curve))
	result = append(result, hashedPublicKey...)
	return result, nil

}

func (k Keychain) BuildTransaction(transaction *TransactionBuilder, serviceName string, index uint8) error {
	pubKey, privKey, err := k.DeriveKeypair(serviceName, index)
	if err != nil {
		return err
	}
	address, err := k.DeriveAddress(serviceName, index+1)
	if err != nil {
		return err
	}
	transaction.SetAddress(address)

	payloadForPreviousSignature := transaction.previousSignaturePayload()
	previousSignature, err := Sign(privKey, payloadForPreviousSignature)
	if err != nil {
		return err
	}

	transaction.SetPreviousSignatureAndPreviousPublicKey(previousSignature, pubKey)

	return nil
}
