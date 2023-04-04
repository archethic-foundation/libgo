# Archethic's golang library

Official Archethic golang library


## Installing

```bash
go get github.com/archethic-foundation/archethic-cli
```

## Usage

This library aims to provide an easy way to create Archethic transaction and to send them over the network.

It supports the Archethic Cryptography rules which are:

- Algorithm identification: keys are prepared by metadata bytes to indicate the curve used and the origin of the generation, and hashes are prepended by a byte to indicate the hash algorithm used. 
  Those information help during the verification
  
  ```

      Ed25519   Software Origin   Public key
        |          |              |
        |  |-------|              |
        |  |   |------------------|        
        |  |   |     
      <<0, 0, 106, 58, 193, 73, 144, 121, 104, 101, 53, 140, 125, 240, 52, 222, 35, 181,
      13, 81, 241, 114, 227, 205, 51, 167, 139, 100, 176, 111, 68, 234, 206, 72>>

       NIST P-256  Software Origin   Public key
        |            |              |
        |  |---------|              |
        |  |  |----------------------
        |  |  |    
      <<1, 0, 4, 7, 161, 46, 148, 183, 43, 175, 150, 13, 39, 6, 158, 100, 2, 46, 167,
       101, 222, 82, 108, 56, 71, 28, 192, 188, 104, 154, 182, 87, 11, 218, 58, 107,
      222, 154, 48, 222, 193, 176, 88, 174, 1, 6, 154, 72, 28, 217, 222, 147, 106,
      73, 150, 128, 209, 93, 99, 115, 17, 39, 96, 47, 203, 104, 34>>
  ```
  
- Key derivation:
  
    To be able to retrieve previous public key, the Archethic network designs the key derivation through a seed (passphrase) and an index(number of
     previous public keys/transactions).
    The procedure is described as follows:
    
    ```
    The seed generates a master key and an entropy used in the child keys generation.

                                                               / (256 bytes) Next private key
                          (256 bytes) Master key  --> HMAC-512
                        /                              Key: Master entropy,
      seed --> HMAC-512                                Data: Master key + index)
                        \
                         (256 bytes) Master entropy

    ```  
## API

  <details>
  <summary>Cryptographic functions</summary>
  <br/>

  #### deriveKeyPair(seed, index, curve)
  It creates a new keypair into hexadecimal format

  - `seed` is a slice of bytes representing the transaction chain seed to be able to derive and generate the keys
  - `index` is the number of transactions in the chain, to generate the actual and the next public key (see below the cryptography section)
  - `curve` is the elliptic curve to use for the key generation (can be "ED25519", "P256", "SECP256K1")

```go
import (
    ...
	archethic "github.com/archethic-foundation/libgo"
)

    publicKey, privateKey := archethic.DeriveKeypair([]byte("seed"), uint32(0), archethic.ED25519)
    publicKeyHex := hex.EncodeToString(publicKey)
    // publicKeyHex: 000161d6cd8da68207bd01198909c139c130a3df3a8bd20f4bacb123c46354ccd52c

```

  #### deriveAddress(seed, index, curve, hashAlgo)
  It creates a transaction address by extract the public key from the key derivation and hash it into a hexadecimal format

   - `seed` is a slice of bytes representing the transaction chain seed to be able to derive and generate the keys
   - `index` is the number of transactions in the chain, to generate the actual and the next public key (see below the cryptography section)
   - `curve` is the elliptic curve to use for the key generation (can be "ED25519", "P256", "SECP256K1")
   - `hashAlgo` is the hash algorithm to create the address (can be "SHA256", "SHA512", "SHA3_256", "SHA3_512", "BLAKE2B")

   ```go
   import(
    ...
    archethic "github.com/archethic-foundation/libgo"
    )
   address := archethic.DeriveAddress([]byte("mysuperseed"), uint32(0), archethic.ED25519, archethic.SHA256)
   // Address: 0000b0c17f85ca19e3db670992e79adb94fb560bd750fda06d45bc0a42912c89d31e
   ```

  #### ecEncrypt(data, publicKey)
  Perform an ECIES encryption using a public key and a data
  
  - `data` Data to encrypt
  - `publicKey` Public key to derive a shared secret and for whom the content must be encrypted
  
  ```go
  import (
    ...
	archethic "github.com/archethic-foundation/libgo"
    )

  	textToEncrypt := []byte("hello")
	publicKey, _ := archethic.DeriveKeypair([]byte("seed"), 0, archethic.P256)
	cipherText := archethic.EcEncrypt(textToEncrypt, publicKey)
  ```

  #### aesEncrypt(data, publicKey)
  Perform an AES encryption using a key and a data

  - `data` Data to encrypt
  - `key` Symmetric key

  ```go
    import (
    ...
	archethic "github.com/archethic-foundation/libgo"
    )

    key := make([]byte, 32)
	rand.Read(key)
	dataToEncrypt := []byte("hello")
	encryptedData := archethic.AesEncrypt(dataToEncrypt, key)
  ```

  </details>
   <br/>
   <details>
   <summary>Transaction building</summary>
   <br/>

  `tx := archethic.TransactionBuilder{}` creates a new instance of the transaction
  
  The transaction instance contains the following methods:
  
  #### SetType(type)
  Sets the type of the transaction (could be `TransferType`, `ContractType`, `DataType`, `TokenType`, `HostingType`, `CodeProposalType`, `CodeApprovalType`)

  #### SetCode(code)
  Adds the code in the `data.code` section of the transaction
  `code` is a string defining the smart contract
  
  #### SetContent(content)
  Adds the content in the `data.content` section of the transaction
  `content` is a string defining the smart contract
  
  #### AddOwnership(secret, authorizedKeys)
   Adds an ownership in the `data.ownerships` section of the transaction with a secret and its related authorized public keys to be able to decrypt it.
   This aims to prove the ownership or the delegatation of some secret to a given list of public keys.
  `secret` is the slice of bytes representing the encrypted secret
  `authorizedKeys` is a list of object represented by 
  - `publicKey` is the slice of bytes representing the public key
  - `encryptedSecretKey` is the slice of bytes representing the secret key encrypted with the public key (see `ecEncrypt`)

  #### AddUCOTransfer(to, amount)
  Adds a UCO transfer to the `data.ledger.uco.transfers` section of the transaction
  - `to` is the slice of bytes representing the transaction address (recipient) to receive the funds
  - `amount` is the number of uco to send, the `ToUint64(number float64, decimals int) uint64` function can help build the proper amount, for example `ToUint64(10.03, 8)`

  #### AddTokenTransfer(to, tokenAddress, amount, tokenId)
  Adds a token transfer to the `data.ledger.token.transfers` section of the transaction
  - `to` is the slice of bytes representing the transaction address (recipient) to receive the funds
  - `tokenAddress` is the slice of bytes representing the token address to spend
  - `amount` is the number of uco to send, the `ToUint64(number float64, decimals int) uint64` function can help build the proper amount, for example `ToUint64(10.03, 8)`
  - `tokenId` is the ID of the token to use

  #### AddRecipient(to)
  Adds a recipient (for non UCO transfers, ie. smart contract interaction) to the `data.recipient` section of the transaction
  - `to` is the slice of bytes representing the transaction address (recipient)
  
  #### Build(seed, index, curve, hashAlgo)
  Generates `address`, `timestamp`, `previousPublicKey`, `previousSignature` of the transaction and 
  serialize it using a custom binary protocol.
  
  - `seed` is the slice of bytes representing the transaction chain seed to be able to derive and generate the keys
  - `index` is the number of transactions in the chain, to generate the actual and the next public key (see below the cryptography section)
  - `curve` is the elliptic curve to use for the key generation (can be "ED25519", "P256", "SECP256K1")
  - `hashAlgo` is the hash algorithm to use to generate the address (can be "SHA256", "SHA512", "SHA3_256", "SHA3_512", "BLAKE2B")
  
  ```go
  
  import(
    ...
    archethic "github.com/archethic-foundation/libgo"
    )
    tx := archethic.TransactionBuilder{}
	tx.SetType(archethic.TransferType)
	ucoAddress, _ := hex.DecodeString("0000b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646")

	tx.AddUcoTransfer(
		ucoAddress,
		archethic.ToUint64(0.420, 8),
	)
	tx.Build([]byte("mysuperpassphraseorseed"), 0, archethic.ED25519, archethic.SHA256)

  ```

  #### OriginSign(privateKey)
  Sign the transaction with an origin device private key

   - `privateKey` is the slice of bytes representing the private key to generate the origin signature to able to perform the ProofOfWork and authorize the transaction

  ```go
    import(
    ...
    archethic "github.com/archethic-foundation/libgo"
    )

    originPublicKey, originPrivateKey := archethic.DeriveKeypair([]byte("origin_seed"), 0, archethic.P256)

	tx := archethic.TransactionBuilder{}
	tx.SetType(archethic.TransferType)

	tx.Build([]byte("seed"), 0, archethic.P256, archethic.SHA256)
	tx.OriginSign(originPrivateKey)
	log.Println(tx.Version)

	// test, err := archethic.Verify(tx.OriginSignature, tx.OriginSignaturePayload(), originPublicKey)
  ```

  #### ToJSON()
  Export the transaction generated into JSON

   ```go
   import(
    ...
    archethic "github.com/archethic-foundation/libgo"
    )

    tx := archethic.TransactionBuilder{}
	tx.SetType(archethic.TransferType)
	ucoAddress, _ := hex.DecodeString("0000b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646")

	tx.AddUcoTransfer(
		ucoAddress,
		archethic.ToUint64(0.420, 8),
	)
	tx.Build([]byte("mysuperpassphraseorseed"), 0, archethic.ED25519, archethic.SHA256)
    json, _ := tx.ToJSON()
  ```
  
  </details>
   <br/>
   <details>
   <summary>Remote Endpoint calls</summary>
   <br/>

  #### GetOriginKey()
  Return the hardcoded origin private key for software, this is used for signing transaction (see OriginSign).

  #### AddOriginKey(originPublicKey, certificate, endpoint)
  Query a node to add a new origin public to be authorized to sign transaction with the corresponding private key (see OriginSign).

  - `originPublicKey` is the public key to be added.
  - `certificate` is the certificate that prove the public key is allowed to be added.

  ```golang
    client := archethic.NewAPIClient("http://localhost:4000")

    client.AddOriginKey("01103109", "mycertificate")
  ```

  #### GetLastTransactionIndex(address)
  Query a node to find the length of the chain to retrieve the transaction index

  - `addresses` Transaction address (in hexadecimal)

  ```golang
    client := archethic.NewAPIClient("http://localhost:4000")
    client.GetLastTransactionIndex("0000872D96130A2963F1195D1F85FC316AE966644F2E3EE45469C2A257F49C4631C2")
  ``` 

  #### GetStorageNoncePublicKey()
  Query a node to find the public key of the shared storage node key

   ```golang
  	client := archethic.NewAPIClient("https://testnet.archethic.net/api")
	client.GetStorageNoncePublicKey()
    // 00017877BCF4122095926A49489009649603AB129822A19EF9D573B8FD714911ED7F
  ``` 

  #### GetTransactionFee(tx)
  Query a node to fetch the tx fee for a given transaction
  
  - `tx` Generated transaction
  
  ```golang
  
    client := archethic.NewAPIClient("http://localhost:4000")

	tx := archethic.TransactionBuilder{}
	tx.SetType(archethic.TransferType)
	ucoAddress, _ := hex.DecodeString("0000b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646")

	tx.AddUcoTransfer(
		ucoAddress,
		archethic.ToUint64(0.420, 8),
	)
	tx.Build([]byte("mysuperpassphraseorseed"), 0, archethic.ED25519, archethic.SHA256)
	client.GetTransactionFee(&tx)
  ```

  #### GetTransactionOwnerships(addresses)
  Query a node to find the ownerships (secrets and authorized keys) to given transactions addresses

  - `addresses`: Transaction address

  ```golang
    client := archethic.NewAPIClient("http://localhost:4000")
    client.GetTransactionOwnerships("0000872D96130A2963F1195D1F85FC316AE966644F2E3EE45469C2A257F49C4631C2")

  ```

  </details>
   <br/>
   <details>
   <summary>Keychain / Wallet management</summary>
   <br/>

  #### NewKeychainTransaction(seed []byte, authorizedPublicKeys [][]byte) TransactionBuilder
  Creates a new transaction to build a keychain by embedding the on-chain encrypted wallet.

  - `seed` Keychain's seed
  - `authorizedPublicKeys` List of authorized public keys able to decrypt the wallet

  #### NewAccessTransaction(seed []byte, keychainAddress []byte) TransactionBuilder
  Creates a new keychain access transaction to allow a seed and its key to access a keychain

  - `seed` Keychain access's seed
  - `keychainAddress` Keychain's tx address

  #### GetKeychain(seed []byte, client APIClient) *Keychain
  Retrieve a keychain from the keychain access transaction and decrypt the wallet to retrieve the services associated

  - `seed` Keychain access's seed
  - `client` the API client

  ```go
  client := archethic.NewAPIClient("http://localhost:4000")
  keychain := archethic.GetKeychain([]byte("seed"), *client)
  ```  

  Once retrieved the keychain provide the following methods:

  #### (k Keychain) BuildTransaction(transaction TransactionBuilder, serviceName string, index uint8) TransactionBuilder
  Generate `address`, `previousPublicKey`, `previousSignature` of the transaction and 
  serialize it using a custom binary protocol, based on the derivation path, curve and hash algo of the service given in param.

  - `transaction` is an instance of `TransactionBuilder`
  - `serviceName` is the service name to use for getting the derivation path, the curve and the hash algo
  - `index` is the number of transactions in the chain, to generate the actual and the next public key (see the cryptography section)

  Returns is the signed `TransactionBuilder`. 

  ```go

  seed := []byte("seed")

  keychain := archethic.Keychain{Seed: seed, Version: 1, Services: map[string]Service{
    "uco": {
      DerivationPath: "m/650'/0/0",
      Curve:          ED25519,
      HashAlgo:       SHA256,
    },
  }}

  tx := archethic.TransactionBuilder{TxType: TransferType}
  ucoAddress, _ := hex.DecodeString("0000b1d3750edb9381c96b1a975a55b5b4e4fb37bfab104c10b0b6c9a00433ec4646")
  tx.AddUcoTransfer(
    ucoAddress,
    archethic.ToUint64(10.0, 8),
  )

  tx = keychain.BuildTransaction(tx, "uco", 0)

  ```

  #### (k Keychain) DeriveAddress(serviceName string, index uint8) []byte
  Derive an address for the given service at the index given

  - `service`: Service name to identify the derivation path to use
  - `index`: Chain index to derive

  ```go
  seed := []byte("abcdefghijklmnopqrstuvwxyz")
	keychain := archethic.NewKeychain(seed)
	publicKey, _ := keychain.DeriveKeypair("uco", 0)
	address := archethic.DeriveAddress(seed, 0, keychain.Services["uco"].Curve, keychain.Services["uco"].HashAlgo)
  ``` 

  #### (k Keychain) DeriveKeypair(serviceName string, index uint8) ([]byte, []byte)
  Derive a keypair for the given service at the index given

  - `service`: Service name to identify the derivation path to use
  - `index`: Chain index to derive
  
  ```go
  seed := []byte("abcdefghijklmnopqrstuvwxyz")
	keychain := archethic.NewKeychain(seed)
	publicKey, _ := keychain.DeriveKeypair("uco", 0)
  ``` 

  #### (k Keychain) ToDID() DID
  Return a Decentralized Identity document from the keychain. (This is used in the transaction's content of the keychain tx)

  ```go
  seed := []byte("abcdefghijklmnopqrstuvwxyz")
	keychain := archethic.NewKeychain(seed)
	did := keychain.ToDID()
  log.Println(string(did.ToJSON()))

  {
    "@context": [
       "https://www.w3.org/ns/did/v1"
    ],
    "id": "did:archethic:keychain_address",
    "authentification": servicesMaterials, //list of public keys of the services
    "verificationMethod": servicesMaterials //list of public keys of the services
  }
  ```

  #### (k *Keychain) AddService(name string, derivationPath string, curve Curve, hashAlgo HashAlgo)
  Add a service into the keychain

  - `name`: Name of the service to add
  - `derivationPath`: Crypto derivation path
  - `curve`: Elliptic curve to use
  - `hashAlgo`: Hash algo

  ```go
  	keychain := archethic.NewKeychain([]byte("seed"))
	keychain.AddService("nft1", "m/650'/1/0", archethic.ED25519, archethic.SHA256)
	log.Println(keychain.Services)
  //map[nft1:{m/650'/1/0 0 0} uco:{m/650'/0/0 1 0}]
  ```

   <br/>


## Running the tests

```bash
go test
```

