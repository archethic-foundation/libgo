package archethic

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"sync"

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

	done := make(chan bool)
	var wg sync.WaitGroup
	wg.Add(2)

	go c.SubscribeTransactionConfirmed(hex.EncodeToString(tx.address), func() {
		wg.Done()
	}, func(transactionConfirmed TransactionConfirmedGQL) {
		log.Println("Transaction is confirmed")
		log.Println(transactionConfirmed)
		done <- true
	})

	go c.SubscribeTransactionError(hex.EncodeToString(tx.address), func() {
		wg.Done()
	}, func(transactionError TransactionErrorGQL) {
		log.Println("Error during transaction")
		log.Println(transactionError)
		done <- true
	})

	wg.Wait()

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
	<-done
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

func (c *APIClient) SubscribeToOracleUpdates(handler func(OracleDataWithTimestampGQL)) {
	query := `subscription{
				oracleUpdate{
					services{
						uco {eur usd}
					}
					timestamp
				}
			}`
	graphqlSubscription(c.wsUrl, query, nil, nil, func(data map[string]interface{}) {
		var response struct {
			OracleUpdate OracleDataWithTimestampGQL
		}

		jsonStr, err := json.Marshal(data)
		if err != nil {
			fmt.Println(err)
		}

		if err := json.Unmarshal(jsonStr, &response); err != nil {
			fmt.Println(err)
		}

		handler(response.OracleUpdate)
	})
}

func (c *APIClient) SubscribeTransactionError(transactionAddress string, readyHandler func(), handler func(TransactionErrorGQL)) {

	query := `subscription ($address: Address!){
		transactionError(address: $address) {
			context
			reason
		}
	}`
	variables := make(map[string]string)
	variables["address"] = transactionAddress

	graphqlSubscription(c.wsUrl, query, variables, readyHandler, func(data map[string]interface{}) {
		var response struct {
			TransactionError TransactionErrorGQL
		}

		jsonStr, err := json.Marshal(data)
		if err != nil {
			fmt.Println(err)
		}

		if err := json.Unmarshal(jsonStr, &response); err != nil {
			fmt.Println(err)
		}

		handler(response.TransactionError)
	})
}

func (c *APIClient) SubscribeTransactionConfirmed(transactionAddress string, readyHandler func(), handler func(TransactionConfirmedGQL)) {

	query := `subscription ($address: Address!){
		transactionConfirmed(address: $address) {
			nbConfirmations
			maxConfirmations
		}
	}`
	variables := make(map[string]string)
	variables["address"] = transactionAddress

	graphqlSubscription(c.wsUrl, query, variables, readyHandler, func(data map[string]interface{}) {
		var response struct {
			TransactionConfirmed TransactionConfirmedGQL
		}

		jsonStr, err := json.Marshal(data)
		if err != nil {
			fmt.Println(err)
		}

		if err := json.Unmarshal(jsonStr, &response); err != nil {
			fmt.Println(err)
		}

		handler(response.TransactionConfirmed)
	})
}

func graphqlSubscription(wsUrl, query string, variables map[string]string, readyHandler func(), handler func(map[string]interface{})) {
	endPoint, _ := url.Parse(wsUrl)

	// Create a new phx.Socket
	socket := phx.NewSocket(endPoint)

	// Wait for the socket to connect before continuing. If it's not able to, it will keep
	// retrying forever.
	cont := make(chan bool)
	socket.OnOpen(func() {
		cont <- true
	})

	// Tell the socket to connect (or start retrying until it can connect)
	err := socket.Connect()
	if err != nil {
		log.Fatal(err)
	}

	// Wait for the connection
	<-cont

	// Create a phx.Channel to connect to the default '__absinthe__:control' channel with no params
	channel := socket.Channel("__absinthe__:control", nil)

	//TODO: implement hearbeat

	// Join the channel. A phx.Push is returned which can be used to bind to replies and errors
	join, err := channel.Join()
	if err != nil {
		log.Fatal(err)
	}

	// Listen for a response and only continue once we know we're joined
	join.Receive("ok", func(response any) {
		log.Println("Joined channel:", channel.Topic(), response)
		cont <- true
	})
	join.Receive("error", func(response any) {
		log.Println("Join error", response)
	})

	// wait to be joined
	<-cont

	payload := make(map[string]any)
	payload["query"] = query
	if variables != nil {
		payload["variables"] = variables
	}

	_, err = channel.Push("doc", payload)
	if err != nil {
		log.Fatal(err)
	}

	subscriptionID := ""
	channel.On("phx_reply", func(data interface{}) {
		dataMap, ok := data.(map[string]interface{})
		if !ok {
			log.Fatalf("'phx_reply' error to parse data: %s", data)
		}

		response, ok := dataMap["response"].(map[string]interface{})
		if !ok {
			log.Fatalf("'phx_reply' error to parse response: %s", dataMap)
		}

		subscriptionID, ok = response["subscriptionId"].(string)
		if !ok {
			log.Fatalf("'phx_reply' error to parse subscriptionID: %s", response)
		}

		if subscriptionID != "" {
			log.Printf("SubscriptionID: %s", subscriptionID)
			cont <- true
		}
	})

	<-cont

	socket.OnMessage(func(message phx.Message) {
		if message.Topic == subscriptionID && message.Event == "subscription:data" {
			payload, ok := message.Payload.(map[string]interface{})
			if !ok {
				log.Fatalf("Message received, error to parse payload: %s", message.Payload)
			}
			result, ok := payload["result"].(map[string]interface{})
			if !ok {
				log.Fatalf("Message received, error to parse result %s", payload)
			}
			data, ok := result["data"].(map[string]interface{})
			if !ok {
				log.Fatalf("Message received, error to parse data %s", result)
			}

			handler(data)

			cont <- true
		}
	})

	if readyHandler != nil {
		readyHandler()
	}
	<-cont

	// Now we will block forever, hit ctrl+c to exit
	select {}
}
