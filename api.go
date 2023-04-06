package archethic

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/hasura/go-graphql-client"
	"github.com/nshafer/phx"
)

type Address string
type Hex string
type PublicKey string
type TokenProperties map[string]interface{}

type Timestamp int64

func (t Timestamp) GetGraphQLType() string { return "Timestamp" }

type Fee struct {
	Fee   float32
	Rates struct {
		Eur float32
		Usd float32
	}
}

type Ownerships []struct {
	Secret               []byte
	AuthorizedPublicKeys []struct {
		EncryptedSecretKey []byte
		PublicKey          []byte
	}
}

type OwnershipsGQL []struct {
	Secret               Hex
	AuthorizedPublicKeys []struct {
		EncryptedSecretKey Hex
		PublicKey          PublicKey
	}
}

type TransactionOwnershipsGQL struct {
	Transaction struct {
		Data struct {
			Ownerships OwnershipsGQL
		}
	} `graphql:"transaction(address: $address)"`
}

type LastTransactionOwnershipsGQL struct {
	LastTransaction struct {
		Data struct {
			Ownerships OwnershipsGQL
		}
	} `graphql:"lastTransaction(address: $address)"`
}

type NearestEndpointsGQL struct {
	NearestEndpoints []struct {
		IP   string
		Port int
	}
}

type Token struct {
	Genesis    []byte
	Name       string
	Symbol     string
	Supply     int
	Type       string
	Properties [2]interface{}
	Collection [][2]interface{}
	Id         string
	Decimals   int
}

type TokenGQL struct {
	Genesis    Address
	Name       string
	Symbol     string
	Supply     int
	Type       string
	Properties [2]interface{}
	Collection [][2]interface{}
	Id         string
	Decimals   int
}

type OracleDataWithTimestampGQL struct {
	Timestamp Timestamp
	Services  struct {
		Uco struct {
			Eur float32
			Usd float32
		}
	}
}

type Balance struct {
	Uco   int
	Token []struct {
		Address []byte
		Amount  int
		TokenId int
	}
}

type BalanceGQL struct {
	Uco   int
	Token []struct {
		Address Address
		Amount  int
		TokenId int
	}
}

type TransactionConfirmedGQL struct {
	NbConfirmations  int
	MaxConfirmations int
}

type ErrorContext string

type TransactionErrorGQL struct {
	Context ErrorContext
	Reason  string
}

type APIClient struct {
	baseURL        string
	wsUrl          string
	graphqlClient  *graphql.Client
	absintheSocket *phx.Socket
	httpClient     *http.Client
}

func NewAPIClient(baseURL string) *APIClient {

	urlObj, _ := url.Parse(baseURL)

	host := urlObj.Host
	protocol := strings.ToLower(urlObj.Scheme)

	var ws_protocol string
	if protocol == "https" {
		ws_protocol = "wss"
	} else {
		ws_protocol = "ws"
	}

	wsUrl := ws_protocol + "://" + host + "/socket"

	baseURL = baseURL + "/api"
	graphqlClient := graphql.NewClient(baseURL, nil)
	absintheSocket := new(phx.Socket)
	return &APIClient{baseURL, wsUrl, graphqlClient, absintheSocket, http.DefaultClient}
}

func (c *APIClient) InjectHTTPClient(httpClient *http.Client) {
	c.httpClient = httpClient
	c.graphqlClient = graphql.NewClient(c.baseURL, httpClient)
}

func (c *APIClient) GetNearestEndpoints() NearestEndpointsGQL {
	var query NearestEndpointsGQL
	err := c.graphqlClient.Query(context.Background(), &query, nil)
	if err != nil {
		panic(err)
	}
	return query

}

func (c *APIClient) GetLastTransactionIndex(address string) int {

	var query struct {
		LastTransaction struct {
			ChainLength int
		} `graphql:"lastTransaction(address: $address)"`
	}

	variables := map[string]interface{}{
		"address": Address(address),
	}
	err := c.graphqlClient.Query(context.Background(), &query, variables)
	if err != nil {
		return 0
	}
	return query.LastTransaction.ChainLength
}

func (c *APIClient) GetStorageNoncePublicKey() string {

	var query struct {
		SharedSecrets struct {
			StorageNoncePublicKey string
		}
	}
	err := c.graphqlClient.Query(context.Background(), &query, nil)
	if err != nil {
		panic(err)
	}
	return query.SharedSecrets.StorageNoncePublicKey
}

func (c *APIClient) GetTransactionFee(tx *TransactionBuilder) Fee {

	payload, err := tx.ToJSON()
	if err != nil {
		panic(err)
	}
	transactionFeeUrl := c.baseURL + "/transaction_fee"
	req, err := http.NewRequest("POST", transactionFeeUrl, bytes.NewReader(payload))
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		panic(err)
	}
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	var fee Fee
	json.Unmarshal(respBody, &fee)
	return fee
}

func (c *APIClient) GetTransactionOwnerships(address string) Ownerships {

	var query TransactionOwnershipsGQL

	variables := map[string]interface{}{
		"address": Address(address),
	}
	err := c.graphqlClient.Query(context.Background(), &query, variables)
	if err != nil {
		panic(err)
	}
	result := make(Ownerships, len(query.Transaction.Data.Ownerships))
	for i, ownership := range query.Transaction.Data.Ownerships {
		result[i].Secret, err = hex.DecodeString(string(ownership.Secret))
		if err != nil {
			panic(err)
		}
		result[i].AuthorizedPublicKeys = make([]struct {
			EncryptedSecretKey []byte
			PublicKey          []byte
		}, len(ownership.AuthorizedPublicKeys))
		for j, authorizedPublicKey := range ownership.AuthorizedPublicKeys {
			result[i].AuthorizedPublicKeys[j].PublicKey, err = hex.DecodeString(string(authorizedPublicKey.PublicKey))
			if err != nil {
				panic(err)
			}
			result[i].AuthorizedPublicKeys[j].EncryptedSecretKey, err = hex.DecodeString(string(authorizedPublicKey.EncryptedSecretKey))
			if err != nil {
				panic(err)
			}
		}
	}

	return result
}

func (c *APIClient) GetLastTransactionOwnerships(address string) Ownerships {

	var query LastTransactionOwnershipsGQL

	variables := map[string]interface{}{
		"address": Address(address),
	}
	err := c.graphqlClient.Query(context.Background(), &query, variables)
	if err != nil {
		panic(err)
	}
	result := make(Ownerships, len(query.LastTransaction.Data.Ownerships))
	for i, ownership := range query.LastTransaction.Data.Ownerships {
		result[i].Secret, err = hex.DecodeString(string(ownership.Secret))
		if err != nil {
			panic(err)
		}
		result[i].AuthorizedPublicKeys = make([]struct {
			EncryptedSecretKey []byte
			PublicKey          []byte
		}, len(ownership.AuthorizedPublicKeys))
		for j, authorizedPublicKey := range ownership.AuthorizedPublicKeys {
			result[i].AuthorizedPublicKeys[j].PublicKey, err = hex.DecodeString(string(authorizedPublicKey.PublicKey))
			if err != nil {
				panic(err)
			}
			result[i].AuthorizedPublicKeys[j].EncryptedSecretKey, err = hex.DecodeString(string(authorizedPublicKey.EncryptedSecretKey))
			if err != nil {
				panic(err)
			}
		}
	}

	return result
}

func (c *APIClient) GetToken(address string) Token {

	var query struct {
		Token TokenGQL `graphql:"token(address: $address)"`
	}

	variables := map[string]interface{}{
		"address": Address(address),
	}
	err := c.graphqlClient.Query(context.Background(), &query, variables)
	if err != nil {
		panic(err)
	}

	genesisAddress, err := hex.DecodeString(string(query.Token.Genesis))
	if err != nil {
		panic(err)
	}

	return Token{
		Genesis:    genesisAddress,
		Name:       query.Token.Name,
		Symbol:     query.Token.Symbol,
		Supply:     query.Token.Supply,
		Type:       query.Token.Type,
		Properties: query.Token.Properties,
		Collection: query.Token.Collection,
		Id:         query.Token.Id,
		Decimals:   query.Token.Decimals,
	}

}

func (c *APIClient) AddOriginKey(originPublicKey, certificate string) {
	addOriginKeyUrl := c.baseURL + "/origin_key"

	data := map[string]string{
		"origin_public_key": originPublicKey,
		"certificate":       certificate,
	}
	payload, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}

	req, err := http.NewRequest("POST", addOriginKeyUrl, bytes.NewBuffer(payload))
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	_, err = c.httpClient.Do(req)
	if err != nil {
		panic(err)
	}
}

func (c *APIClient) GetOracleData(timestamp ...int64) OracleDataWithTimestampGQL {

	if timestamp == nil {

		var query struct{ OracleData OracleDataWithTimestampGQL }
		err := c.graphqlClient.Query(context.Background(), &query, nil)
		if err != nil {
			panic(err)
		}

		return query.OracleData

	} else {

		var query struct {
			OracleData OracleDataWithTimestampGQL `graphql:"oracleData(timestamp: $timestamp)"`
		}
		variables := map[string]interface{}{
			"timestamp": Timestamp(timestamp[0]),
		}
		err := c.graphqlClient.Query(context.Background(), &query, variables)
		if err != nil {
			panic(err)
		}
		return query.OracleData
	}
}

func (c *APIClient) GetBalance(address string) Balance {

	var query struct {
		Balance BalanceGQL `graphql:"balance(address: $address)"`
	}

	variables := map[string]interface{}{
		"address": Address(address),
	}
	err := c.graphqlClient.Query(context.Background(), &query, variables)
	if err != nil {
		panic(err)
	}

	tokens := make([]struct {
		Address []byte
		Amount  int
		TokenId int
	},
		len(query.Balance.Token))
	for i, token := range query.Balance.Token {
		tokens[i].Address, err = hex.DecodeString(string(token.Address))
		if err != nil {
			panic(err)
		}
		tokens[i].Amount = token.Amount
		tokens[i].TokenId = token.TokenId
	}
	return Balance{
		Uco:   query.Balance.Uco,
		Token: tokens,
	}
}

func (c *APIClient) SubscribeToOracleUpdates(handler func(OracleDataWithTimestampGQL)) {
	query := `subscription{
				oracleUpdate{
					services{
						uco {eur usd}
					}
					timestamp
				}
			}`
	subscription := new(AbsintheSubscription)
	subscription.GraphqlSubscription(c.wsUrl, query, nil, nil, func(data map[string]interface{}) {
		var response struct {
			OracleUpdate OracleDataWithTimestampGQL
		}

		jsonStr, err := json.Marshal(data)
		if err != nil {
			panic(err)
		}

		if err := json.Unmarshal(jsonStr, &response); err != nil {
			panic(err)
		}

		handler(response.OracleUpdate)
	})
}
