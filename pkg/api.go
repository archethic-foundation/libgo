package archethic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/hasura/go-graphql-client"
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

type NearestEndpointsGQL struct {
	NearestEndpoints []struct {
		IP   string
		Port int
	}
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

type BalanceGQL struct {
	Uco   int
	Token []struct {
		Address Address
		Amount  int
		TokenId int
	}
}

type APIClient struct {
	baseURL       string
	wsUrl         string
	graphqlClient *graphql.Client
	httpClient    *http.Client
}

func NewAPIClient(baseURL, wsUrl string) *APIClient {
	graphqlClient := graphql.NewClient(baseURL, nil)
	return &APIClient{baseURL, wsUrl, graphqlClient, http.DefaultClient}
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
		panic(err)
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
		fmt.Printf("could not read response body: %s\n", err)
	}

	var fee Fee
	json.Unmarshal(respBody, &fee)
	return fee
}

func (c *APIClient) SendTransaction(tx *TransactionBuilder) {

	//TODO: implement the connection to the 2 graphql subscriptions
	// subscription {
	// 	transactionConfirmed(address: "${address}") {
	// 	  nbConfirmations,
	// 	  maxConfirmations
	// 	}
	//   }
	// 	subscription {
	// 	  transactionError(address: "${address}") {
	// 		context,
	// 		reason
	// 	  }
	// 	}
	// BUT... same problem with oracle update (we don't have the phoenix channel / absinthe payload)

	payload, err := tx.ToJSON()
	if err != nil {
		panic(err)
	}
	transactionFeeUrl := c.baseURL + "/transaction"
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
	fmt.Printf("request body: %s\n", respBody)
}

func (c *APIClient) GetTransactionOwnerships(address string) OwnershipsGQL {

	var query TransactionOwnershipsGQL

	variables := map[string]interface{}{
		"address": Address(address),
	}
	err := c.graphqlClient.Query(context.Background(), &query, variables)
	if err != nil {
		panic(err)
	}
	return query.Transaction.Data.Ownerships
}

func (c *APIClient) GetToken(address string) TokenGQL {

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
	return query.Token
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

func (c *APIClient) GetBalance(address string) BalanceGQL {

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
	return query.Balance
}
