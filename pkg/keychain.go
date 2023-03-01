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
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type Keychain struct {
	seed     []byte
	version  uint8
	services map[string]Service
}

type Service struct {
	derivationPath string
	curve          Curve
	hashAlgo       HashAlgo
}

type DID struct {
	context            []string
	id                 string
	authentication     []DIDKeyMaterial
	verificationMethod []DIDKeyMaterial
}

type DIDKeyMaterial struct {
	id           string
	keyType      string
	publicKeyJwk map[string]string
}

func (s Service) toBytes() []byte {
	buf := make([]byte, 0)
	buf = append(buf, byte(len(s.derivationPath)))
	buf = append(buf, []byte(s.derivationPath)...)
	buf = append(buf, byte(s.curve))
	buf = append(buf, byte(s.hashAlgo))
	return buf
}

// NewKeychain instanciates a new Keychain struct
func NewKeychain(seed []byte) *Keychain {
	return &Keychain{
		seed:    seed,
		version: 1,
		services: map[string]Service{
			"uco": {
				derivationPath: "m/650'/0/0",
				curve:          P256,
				hashAlgo:       SHA256,
			},
		},
	}
}

func (k *Keychain) AddService(name string, derivationPath string, curve Curve, hashAlgo HashAlgo) {
	k.services[name] = Service{
		derivationPath: derivationPath,
		curve:          curve,
		hashAlgo:       hashAlgo,
	}
}

func (k Keychain) ToDID() DID {
	address := DeriveAddress(k.seed, 0, P256, SHA256)
	keyMaterials := make([]DIDKeyMaterial, 0)

	for serviceName, service := range k.services {
		splittedPath := strings.Split(service.derivationPath, "/")
		for i := 0; i < len(splittedPath); i++ {
			splittedPath[i] = strings.ReplaceAll(splittedPath[i], "'", "")
			purpose := splittedPath[i]
			if purpose == "650" {
				publicKey, _ := DeriveArchethicKeypair(k.seed, service.derivationPath, 0, service.curve)
				keyMaterials = append(keyMaterials, DIDKeyMaterial{
					id:           fmt.Sprintf("did:archethic:%x#%s", address, serviceName),
					keyType:      "JsonWebKey2020",
					publicKeyJwk: KeyToJWK(publicKey, serviceName),
				})
			}
		}
	}

	return DID{
		context: []string{
			"https://www.w3.org/ns/did/v1",
		},
		id:                 fmt.Sprintf("did:archethic:%x", address),
		authentication:     keyMaterials,
		verificationMethod: keyMaterials,
	}
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
	binary.BigEndian.PutUint32(version, uint32(k.version))
	buf = append(buf, version...)

	buf = append(buf, byte(len(k.seed)))
	buf = append(buf, k.seed...)
	buf = append(buf, byte(len(k.services)))

	for name, service := range k.services {
		buf = append(buf, byte(len(name)))
		buf = append(buf, []byte(name)...)
		buf = append(buf, service.toBytes()...)
	}

	return buf
}

func (k Keychain) DeriveKeypair(serviceName string, index uint8) ([]byte, []byte) {
	service, ok := k.services[serviceName]

	if !ok {
		panic("Service doesn't exists in the keychain")
	}

	return DeriveArchethicKeypair(k.seed, service.derivationPath, index, service.curve)
}

func DeriveArchethicKeypair(seed []byte, derivationPath string, index uint8, curve Curve) ([]byte, []byte) {
	indexedPath := replaceDerivationPathIndex(derivationPath, index)
	h := sha256.New()
	h.Write([]byte(indexedPath))
	hashedPath := h.Sum(nil)

	hm := hmac.New(sha512.New, seed)
	hm.Write(hashedPath)
	extendedSeed := hm.Sum(nil)
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
		seed:     seed,
		version:  versionInt,
		services: make(map[string]Service),
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
