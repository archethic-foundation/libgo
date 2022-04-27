package archethic

import(
  "crypto/sha256"
  "crypto/sha512"
  "crypto/hmac"
  "crypto/ecdsa"
  "crypto/x509"
  "strings"
  "strconv"
  "bytes"
  "bufio"
  "fmt"
  "math/big"
  "encoding/base64"
  "regexp"
)

type Keychain struct {
   seed []byte
   version uint8
   services map[string]Service
}

type Service struct {
  derivationPath string
  curve Curve
  hashAlgo HashAlgo
}

type DID struct {
  context []string
  id string
  authentication []DIDKeyMaterial
  verificationMethod []DIDKeyMaterial
}

type DIDKeyMaterial struct {
  id string
  keyType string
  publicKeyJwk map[string]string
}

func (s Service) toBytes() []byte{
  buf := make([]byte, 0)
  buf = append(buf, byte(len(s.derivationPath)))
  buf = append(buf, []byte(s.derivationPath)...)
  buf = append(buf, byte(s.curve))
  buf = append(buf, byte(s.hashAlgo))
  return buf
}

//NewKeychain instanciates a new Keychain struct
func NewKeychain(seed []byte) *Keychain{
  return &Keychain{
    seed: seed,
    version: 1,
    services: map[string]Service{
      "uco": {
        derivationPath: "m/650'/0'/0'",
        curve: P256,
        hashAlgo: SHA256,
      },
    },
  }
}

func (k* Keychain) AddService(name string, derivationPath string, curve Curve, hashAlgo HashAlgo) {
  k.services[name] = Service{
    derivationPath: derivationPath,
    curve: curve,
    hashAlgo: hashAlgo,
  }
}

func (k Keychain) ToDID() DID {
   address := DeriveAddress(k.seed, 0, P256, SHA256)
   keyMaterials := make([]DIDKeyMaterial, 0)

   for _, service := range k.services {
     splittedPath := strings.Split(service.derivationPath, "/")
     for i := 0; i < len(splittedPath); i++ {
       splittedPath[i] = strings.ReplaceAll(splittedPath[i], "'", "")
       purpose := splittedPath[0]
       if purpose == "650" {
         publicKey, _ := deriveArchethicKeypair(k.seed, service.derivationPath, 0, service.curve)
         keyMaterials = append(keyMaterials, DIDKeyMaterial{
           id: fmt.Sprintf("did:archethic:%x#key%d", address, len(keyMaterials)),
           keyType: "JsonWebKey2020",
           publicKeyJwk: keyToJWK(publicKey),
         })
       }
     }
   }

   return DID{
      context: []string{
        "https://www.w3.org/ns/did/v1",
      },
      id: fmt.Sprintf("did:archethic:%x", address),
      authentication: keyMaterials,
      verificationMethod: keyMaterials,
   }
}

func keyToJWK(publicKey []byte) map[string]string {
  curveID := publicKey[0]
  keyBytes := publicKey[2:]
  switch Curve(curveID) {
    case P256:
      pub, err := x509.ParsePKIXPublicKey(keyBytes)
      if err != nil {
        panic(err)
      }

      ecdsaKey := pub.(*ecdsa.PublicKey)
      return map[string]string{
        "kty": "EC",
        "crv": "P256",
        "x": pointToBase64Url(ecdsaKey.X),
        "y": pointToBase64Url(ecdsaKey.Y),
      }
    default:
      panic("Unsupported elliptic curve")
  }
}

func pointToBase64Url(p *big.Int) string {
  buf := base64.StdEncoding.EncodeToString(p.Bytes())

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

  buf = append(buf, byte(k.version))
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

  return deriveArchethicKeypair(k.seed, service.derivationPath, index, service.curve)
}

func deriveArchethicKeypair(seed []byte, derivationPath string, index uint8, curve Curve) ([]byte, []byte) {
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

func DecodeKeychain(binary []byte) *Keychain {
  byteReader := bufio.NewReader(bytes.NewReader(binary))
  version, _ := byteReader.ReadByte()
  seedSize, _ := byteReader.ReadByte()
  seed, _ := byteReader.Peek(int(seedSize))
  nbServices, _ := byteReader.ReadByte()

  k  := &Keychain{
    seed: seed,
    version: version,
  }

  for i := 0; i < int(nbServices); i++ {
    serviceNameLength, _ := byteReader.ReadByte()
    serviceName, _ := byteReader.Peek(int(serviceNameLength))
    derivationPathLength, _ := byteReader.ReadByte()
    derivationPath, _ := byteReader.Peek(int(derivationPathLength))
    curveID, _ := byteReader.ReadByte()
    hashAlgoID, _ := byteReader.ReadByte()

    k.AddService(string(serviceName), string(derivationPath), Curve(curveID), HashAlgo(hashAlgoID))
  }

  return k
}
