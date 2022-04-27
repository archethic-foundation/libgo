package archethic

import (
  "crypto/sha256"
  "crypto/sha512"
  "crypto/hmac"
  "crypto/x509"
  "crypto/elliptic"
  "crypto/ecdsa"
  "crypto/rand"
  "encoding/binary"
  "bytes"
)

type HashAlgo uint8
type Curve uint8

const (
   SHA256 HashAlgo = 0
   SHA512 HashAlgo = 1
   SHA3_256 HashAlgo = 2
   SHA3_512 HashAlgo = 3
   BLAKE2B HashAlgo = 4
)

const (
  ED25519 Curve = 0
  P256 Curve = 1
  SECP256K1 Curve = 2
)

const SOFTWARE_ORIGIN_ID = 1

//Hash create a hash digest from the data with an hash algorithm identification prepending the digest
func Hash(content []byte, hashAlgo HashAlgo) []byte {
  digest := hash(content, hashAlgo)
  return append([]byte{byte(hashAlgo)}, digest...)
}

func hash(content []byte, hashAlgo HashAlgo) []byte {
  switch hashAlgo {
    case SHA256:
      h := sha256.New()
      h.Write(content)
      return h.Sum(nil)
    case SHA512:
      h := sha512.New()
      h.Write(content)
      return  h.Sum(nil)
    default:
      panic("Unsupported hash algorithm")
  }
}

//DeriveKeypair generate a keypair using a derivation function with a seed and an index. Each keys is prepending with a curve identification.
func DeriveKeypair(seed []byte, index uint32, curve Curve) ([]byte, []byte) {
  pvKey := derivePrivateKey(seed, index)
  return GenerateDeterministicKeypair(pvKey, curve, SOFTWARE_ORIGIN_ID)
}

func derivePrivateKey(seed []byte, index uint32) []byte {
  h := sha512.New()
  h.Write(seed)
  hash := h.Sum(nil)

  masterKey := hash[:32]
  masterEntropy := hash[32:]

  indexBinary := make([]byte, 4)
  binary.LittleEndian.PutUint32(indexBinary, uint32(index))

  extendedSeed := append(masterKey, indexBinary...)
  h = hmac.New(sha512.New, masterEntropy)
  h.Write(extendedSeed)
  return h.Sum(nil)[:32]
}

//GenerateDeterministicKeypair generate a new keypair deterministically with a given private key, curve and origin id
func GenerateDeterministicKeypair(pvKey []byte, curve Curve, originID uint8) ([]byte, []byte) {
  pubKey := getKeypair(pvKey, curve)
  keyMetadata := []byte{ byte(curve), byte(originID) }

  return append(keyMetadata, pubKey...),append(keyMetadata, pvKey...) 
}

func getKeypair(pvKeyBytes []byte, curve Curve) []byte {
  switch (curve) {
    case P256:
      pvKey, err := x509.ParseECPrivateKey(pvKeyBytes)
      if err != nil {
        panic(err)
      }
      pubKeyBytes := elliptic.Marshal(pvKey.PublicKey.Curve, pvKey.PublicKey.X, pvKey.PublicKey.Y)
      return pubKeyBytes
    default:
      panic("Unsupport elliptic curve")
  }
}

func DeriveAddress(seed []byte, index uint32, curve Curve, hashAlgo HashAlgo) []byte {
  publicKey, _ := DeriveKeypair(seed, index, curve)
  hashedPublicKey := Hash(publicKey, hashAlgo)
  return append([]byte{byte(curve)}, hashedPublicKey...)
}

func Sign(privateKey []byte, data []byte) []byte {
  
  byteReader := bytes.NewReader(privateKey)
  curve, _ := byteReader.ReadByte()
  byteReader.ReadByte()
  
  pvKeyBytes := make([]byte, 0)
  byteReader.Read(pvKeyBytes)

  switch (Curve(curve)) {
    case P256:
      pvKey, err := x509.ParseECPrivateKey(pvKeyBytes)
      if err != nil {
        panic(err)
      }

      sig, err := ecdsa.SignASN1(rand.Reader, pvKey, data)
      if err != nil {
        panic(err)
      }

      return sig
      
    default:
      panic("Unsupported elliptic curve")
  }
}

