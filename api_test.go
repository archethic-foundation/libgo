package archethic

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"reflect"
	"testing"
)

type MockRoundTripper func(r *http.Request) *http.Response

func (f MockRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r), nil
}

func TestGetNearestEndpoints(t *testing.T) {
	client := NewAPIClient("http://localhost:4000")
	client.InjectHTTPClient(&http.Client{
		Transport: MockRoundTripper(func(r *http.Request) *http.Response {
			body, _ := io.ReadAll(r.Body)
			expectedQuery := `{"query":"{nearestEndpoints{ip,port}}"}
`
			if !reflect.DeepEqual(body, []byte(expectedQuery)) {
				t.Errorf("Wrong query for GetNearestEndpoints: expected %s got %s", []byte(expectedQuery), body)
			}

			response := `{
				"data": {
				  "nearestEndpoints": [
					{
					  "ip": "127.0.0.1",
					  "port": 4000
					}
				  ]
				}
			  }`
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(bytes.NewBufferString(response)),
			}
		}),
	})

	result, _ := client.GetNearestEndpoints()
	if result.NearestEndpoints[0].Port != 4000 {
		t.Errorf("Error when getting GetNearestEndpoints.Port expected %d but got %d", 4000, result.NearestEndpoints[0].Port)
	}
	if result.NearestEndpoints[0].IP != "127.0.0.1" {
		t.Errorf("Error when getting GetNearestEndpoints.IP expected %s but got %s", "4000", result.NearestEndpoints[0].IP)
	}
}

func TestGetStorageNoncePublicKey(t *testing.T) {
	client := NewAPIClient("http://localhost:4000")
	client.InjectHTTPClient(&http.Client{
		Transport: MockRoundTripper(func(r *http.Request) *http.Response {
			body, _ := io.ReadAll(r.Body)
			expectedQuery := `{"query":"{sharedSecrets{storageNoncePublicKey}}"}
`
			if !reflect.DeepEqual(body, []byte(expectedQuery)) {
				t.Errorf("Wrong query for GetStorageNoncePublicKey: expected %s got %s", expectedQuery, body)
			}

			response := `{
				"data": {
				  "sharedSecrets": {
					"storageNoncePublicKey": "0001E562F8513ECFAB15920D70848CD63CCEF9CC798696C4ED2DE03553238A7654A4"
				  }
				}
			  }`
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(bytes.NewBufferString(response)),
			}
		}),
	})

	result, _ := client.GetStorageNoncePublicKey()
	expectedKey := "0001E562F8513ECFAB15920D70848CD63CCEF9CC798696C4ED2DE03553238A7654A4"
	if result != expectedKey {
		t.Errorf("Error when getting GetStorageNoncePublicKey expected %s but got %s", expectedKey, result)
	}
}

func TestAddOriginKey(t *testing.T) {
	client := NewAPIClient("http://localhost:4000")
	client.InjectHTTPClient(&http.Client{
		Transport: MockRoundTripper(func(r *http.Request) *http.Response {
			if r.URL.String() != "http://localhost:4000/api/origin_key" {
				t.Errorf("Wrong URL for AddOriginKey: expected %s got %s", "http://localhost:4000/api/origin_key", r.URL.String())
			}
			response := `{ transactionAddress: "addr", status: "pending" }`
			return &http.Response{
				StatusCode: 201,
				Body:       io.NopCloser(bytes.NewBufferString(response)),
			}
		}),
	})

	client.AddOriginKey("01103109", "mycertificate")
}

func TestGetOracleData(t *testing.T) {
	client := NewAPIClient("http://localhost:4000")
	client.InjectHTTPClient(&http.Client{
		Transport: MockRoundTripper(func(r *http.Request) *http.Response {
			body, _ := io.ReadAll(r.Body)
			expectedQuery := `{"query":"{oracleData{timestamp,services{uco{eur,usd}}}}"}
`
			if !reflect.DeepEqual(body, []byte(expectedQuery)) {
				t.Errorf("Wrong query for GetOracleData: expected %s got %s", expectedQuery, body)
			}
			response := `{
				"data": {
				  "oracleData": {
					"services": {
					  "uco": {
						"eur": 0.07653,
						"usd": 0.08148
					  }
					},
					"timestamp": 1678108740
				  }
				}
			  }`
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(bytes.NewBufferString(response)),
			}
		}),
	})

	result, _ := client.GetOracleData()
	if result.Services.Uco.Eur != 0.07653 {
		t.Errorf("Error when getting TestGetOracleData expected %f but got %f", 0.07653, result.Services.Uco.Eur)
	}
}

func TestGetOracleDataWithTimestamp(t *testing.T) {
	client := NewAPIClient("http://localhost:4000")
	client.InjectHTTPClient(&http.Client{
		Transport: MockRoundTripper(func(r *http.Request) *http.Response {
			body, _ := io.ReadAll(r.Body)
			expectedQuery := `{"query":"query ($timestamp:Timestamp!){oracleData(timestamp: $timestamp){timestamp,services{uco{eur,usd}}}}","variables":{"timestamp":1678109849}}
`
			if !reflect.DeepEqual(body, []byte(expectedQuery)) {
				t.Errorf("Wrong query for GetOracleData: expected %s got %s", expectedQuery, body)
			}

			response := `{
					"data": {
					  "oracleData": {
						"services": {
						  "uco": {
							"eur": 0.07653,
							"usd": 0.08148
						  }
						},
						"timestamp": 1678108740
					  }
					}
				  }`
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(bytes.NewBufferString(response)),
			}
		}),
	})

	result, _ := client.GetOracleData(1678109849)
	if result.Services.Uco.Eur != 0.07653 {
		t.Errorf("Error when getting TestGetOracleData expected %f but got %f", 0.07653, result.Services.Uco.Eur)
	}
}

func TestGetToken(t *testing.T) {
	client := NewAPIClient("http://localhost:4000")
	client.InjectHTTPClient(&http.Client{
		Transport: MockRoundTripper(func(r *http.Request) *http.Response {
			body, _ := io.ReadAll(r.Body)
			expectedQuery := `{"query":"query ($address:Address!){token(address: $address){genesis,name,symbol,supply,type,properties,collection{},id,decimals}}","variables":{"address":"1234"}}
`
			if !reflect.DeepEqual(body, []byte(expectedQuery)) {
				t.Errorf("Wrong query for GetStorageNoncePublicKey: expected %s got %s", expectedQuery, body)
			}

			response := `{
				"data": {
				  "token": {
					"collection": [],
					"genesis": "0000D6979F125A91465E29A12F66AE40FA454A2AD6CE3BB40099DBDDFFAF586E195A",
					"id": "9DC6196F274B979E5AB9E3D7A0B03FEE3E4C62C7299AD46C8ECF332A2C5B6574",
					"name": "Mining UCO rewards",
					"supply": 3340000000000000,
					"properties": {},
					"symbol": "MUCO",
					"type": "fungible"
				  }
				}
			  }`
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(bytes.NewBufferString(response)),
			}
		}),
	})

	result, _ := client.GetToken("1234")
	expectedGenesis, _ := hex.DecodeString("0000D6979F125A91465E29A12F66AE40FA454A2AD6CE3BB40099DBDDFFAF586E195A")
	if !bytes.Equal(result.Genesis, expectedGenesis) {
		t.Errorf("Error when getting GetToken expected genesis %s but got %s", expectedGenesis, result.Genesis)
	}

	expectedId := "9DC6196F274B979E5AB9E3D7A0B03FEE3E4C62C7299AD46C8ECF332A2C5B6574"
	if result.Id != expectedId {
		t.Errorf("Error when getting GetToken expected id %s but got %s", expectedId, result.Id)
	}

	expectedSupply := big.NewInt(3340000000000000)
	if !reflect.DeepEqual(expectedSupply, result.Supply) {
		t.Errorf("Error when getting GetToken expected supply %v but got %v", expectedSupply, result.Supply)
	}
}

func TestGetTransactionOwnerships(t *testing.T) {

	address, _ := DeriveAddress([]byte("seed"), 0, ED25519, SHA256)

	client := NewAPIClient("http://localhost:4000")
	client.InjectHTTPClient(&http.Client{
		Transport: MockRoundTripper(func(r *http.Request) *http.Response {
			aesKey := make([]byte, 32)
			rand.Read(aesKey)

			publicKey, _, err := DeriveKeypair([]byte("abc"), 0, ED25519)
			if err != nil {
				t.Error(err)
			}
			encryptedSecretKey, err := EcEncrypt(aesKey, publicKey)
			if err != nil {
				t.Error(err)
			}

			authorizedKeys := []struct {
				EncryptedSecretKey string
				PublicKey          string
			}{
				{
					PublicKey:          hex.EncodeToString(publicKey),
					EncryptedSecretKey: hex.EncodeToString(encryptedSecretKey),
				},
			}

			secret, err := AesEncrypt([]byte("hello"), aesKey)
			if err != nil {
				t.Error(err)
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
				  }}`, hex.EncodeToString(secret), jsonAuthorizedKeys)

			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(bytes.NewBufferString(response)),
			}
		}),
	})

	ownerships, _ := client.GetTransactionOwnerships(hex.EncodeToString(address))
	if len(ownerships) != 1 {
		t.Errorf("Wrong number of ownerships: expected 1 got %d", len(ownerships))
	}
}
