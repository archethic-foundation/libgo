package archethic

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"testing"
)

func TestCreateKeychainTransaction(t *testing.T) {

	pubKey, _ := hex.DecodeString("000161d6cd8da68207bd01198909c139c130a3df3a8bd20f4bacb123c46354ccd52c")
	authorizedPublicKeys := [][]byte{
		pubKey,
	}

	keychain := &Keychain{
		Seed:                 []byte("myseed"),
		AuthorizedPublicKeys: authorizedPublicKeys,
	}

	tx, _ := NewKeychainTransaction(keychain, 0)

	if tx.TxType != KeychainType {
		t.Errorf("Error with type expected %d but got %d", KeychainType, tx.TxType)
	}

	keychainDID, _ := keychain.ToDID()
	if !reflect.DeepEqual(keychainDID.ToJSON(), tx.Data.Content) {
		t.Errorf("Error with content expected %s but got %s", tx.Data.Content, keychainDID.ToJSON())
	}

	if len(tx.Data.Ownerships) != 1 {
		t.Errorf("Error with ownership length expected %d but got %d", 1, len(tx.Data.Ownerships))
	}
	if len(tx.Data.Ownerships[0].AuthorizedKeys) != 1 {
		t.Errorf("Error with authorized keys length expected %d but got %d", 1, len(tx.Data.Ownerships[0].AuthorizedKeys))
	}
	if !reflect.DeepEqual(tx.Data.Ownerships[0].AuthorizedKeys[0].PublicKey, pubKey) {
		t.Errorf("Error with authorized keys expected %d but got %d", pubKey, tx.Data.Ownerships[0].AuthorizedKeys[0].PublicKey)
	}

}

func TestCreateNewAccessKeychainTransaction(t *testing.T) {
	keychainAddress, _ := hex.DecodeString("000161d6cd8da68207bd01198909c139c130a3df3a8bd20f4bacb123c46354ccd52c")
	publicKey, _, _ := DeriveKeypair([]byte("seed"), 0, ED25519)
	tx, _ := NewAccessTransaction([]byte("seed"), keychainAddress)

	if tx.TxType != KeychainAccessType {
		t.Errorf("Error with type expected %d but got %d", KeychainType, tx.TxType)
	}
	if len(tx.Data.Ownerships) != 1 {
		t.Errorf("Error with ownership length expected %d but got %d", 1, len(tx.Data.Ownerships))
	}
	if len(tx.Data.Ownerships[0].AuthorizedKeys) != 1 {
		t.Errorf("Error with authorized keys length expected %d but got %d", 1, len(tx.Data.Ownerships[0].AuthorizedKeys))
	}
	if !reflect.DeepEqual(tx.Data.Ownerships[0].AuthorizedKeys[0].PublicKey, publicKey) {
		t.Errorf("Error with authorized keys expected %d but got %d", publicKey, tx.Data.Ownerships[0].AuthorizedKeys[0].PublicKey)
	}

}

func TestShouldGetKeychain(t *testing.T) {
	client := NewAPIClient("http://localhost:4000")

	publicKey, _, _ := DeriveKeypair([]byte("seed"), 0, ED25519)

	keychain := NewKeychain([]byte("myseed"))
	keychain.AddAuthorizedPublicKey(publicKey)

	keychainTx, _ := NewKeychainTransaction(keychain, 0)
	accessTx, _ := NewAccessTransaction([]byte("seed"), keychainTx.Address)

	client.InjectHTTPClient(&http.Client{
		Transport: MockRoundTripper(func(r *http.Request) *http.Response {
			body, _ := io.ReadAll(r.Body)

			expectedQuery1 := fmt.Sprintf(`{"query":"query ($address:Address!){transaction(address: $address){data{ownerships{secret,authorizedPublicKeys{encryptedSecretKey,publicKey}}}}}","variables":{"address":"%s"}}
`, hex.EncodeToString(accessTx.Address))

			if reflect.DeepEqual(body, []byte(expectedQuery1)) {

				authorizedKeys := make([]map[string]string, len(accessTx.Data.Ownerships[0].AuthorizedKeys))
				for j, a := range accessTx.Data.Ownerships[0].AuthorizedKeys {
					authorizedKeys[j] = map[string]string{
						"publicKey":          hex.EncodeToString(a.PublicKey),
						"encryptedSecretKey": hex.EncodeToString(a.EncryptedSecretKey),
					}
				}

				jsonAuthorizedKeys, _ := json.Marshal(authorizedKeys)
				response := fmt.Sprintf(`{"data": {
					"transaction": {
					  "data": {
						"ownerships": [
						  {
							"secret": "%s",
							"authorizedPublicKeys":
							  %s
						  }
						]
					  }
					}
				  }}`, hex.EncodeToString(accessTx.Data.Ownerships[0].Secret), jsonAuthorizedKeys)

				return &http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(bytes.NewBufferString(response)),
				}
			}

			expectedQuery2 := fmt.Sprintf(`{"query":"query ($address:Address!){lastTransaction(address: $address){data{ownerships{secret,authorizedPublicKeys{encryptedSecretKey,publicKey}}}}}","variables":{"address":"%s"}}
`, hex.EncodeToString(keychainTx.Address))

			if reflect.DeepEqual(body, []byte(expectedQuery2)) {

				authorizedKeys := make([]map[string]string, len(keychainTx.Data.Ownerships[0].AuthorizedKeys))
				for j, a := range keychainTx.Data.Ownerships[0].AuthorizedKeys {
					authorizedKeys[j] = map[string]string{
						"publicKey":          hex.EncodeToString(a.PublicKey),
						"encryptedSecretKey": hex.EncodeToString(a.EncryptedSecretKey),
					}
				}

				jsonAuthorizedKeys, _ := json.Marshal(authorizedKeys)

				response := fmt.Sprintf(`{
				        "data": {
				          "lastTransaction": {
				            "data": {
				              "ownerships": [
				                {
				                  "secret":"%s",
				                  "authorizedPublicKeys":
				                    %s
				                }
				              ]
				            }
				          }
				        }}`, hex.EncodeToString(keychainTx.Data.Ownerships[0].Secret), jsonAuthorizedKeys)
				return &http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(bytes.NewBufferString(response)),
				}
			}

			t.Errorf("Wrong query... got %s but expected either %s or %s", body, string(expectedQuery1), string(expectedQuery2))

			return nil

		}),
	})

	keychainRetrieved, _ := GetKeychain([]byte("seed"), *client)
	if !reflect.DeepEqual(keychain.Seed, keychainRetrieved.Seed) {
		t.Errorf("Wrong keychain's seed returned: %s %s", hex.EncodeToString(keychain.Seed), hex.EncodeToString(keychainRetrieved.Seed))
	}
	if len(keychainRetrieved.Services) != 1 {
		t.Errorf("Wrong number of services: expected 1 got %d", len(keychain.Services))
	}
	if keychainRetrieved.Services["uco"].DerivationPath != "m/650'/0/0" {
		t.Errorf("Wrong derivation path: expected m/650'/0/0 got %s", keychain.Services["uco"].DerivationPath)
	}

}
