package archethic

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/hasura/go-graphql-client"
	"github.com/nshafer/phx"
	"github.com/ybbus/jsonrpc/v3"
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

type OwnershipGQL struct {
	Secret               Hex
	AuthorizedPublicKeys []struct {
		EncryptedSecretKey Hex
		PublicKey          PublicKey
	}
}

type TransactionOwnershipsGQL struct {
	Transaction struct {
		Data struct {
			Ownerships []OwnershipGQL
		}
	} `graphql:"transaction(address: $address)"`
}

type LastTransactionOwnershipsGQL struct {
	LastTransaction struct {
		Data struct {
			Ownerships []OwnershipGQL
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

type OracleData struct {
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
	jsonRpcClient  jsonrpc.RPCClient
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
	baseURLJsonRpc := baseURL + "/rpc"
	graphqlClient := graphql.NewClient(baseURL, nil)
	absintheSocket := new(phx.Socket)

	jsonRpcClient := jsonrpc.NewClient(baseURLJsonRpc)
	return &APIClient{baseURL, wsUrl, graphqlClient, absintheSocket, http.DefaultClient, jsonRpcClient}
}

func (c *APIClient) InjectHTTPClient(httpClient *http.Client) {
	c.httpClient = httpClient
	c.graphqlClient = graphql.NewClient(c.baseURL, httpClient)
}

func (c *APIClient) GetNearestEndpoints() (*NearestEndpointsGQL, error) {
	var query NearestEndpointsGQL
	err := c.graphqlClient.Query(context.Background(), &query, nil)
	if err != nil {
		return nil, err
	}
	return &query, nil

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

func (c *APIClient) GetStorageNoncePublicKey() (string, error) {

	var query struct {
		SharedSecrets struct {
			StorageNoncePublicKey string
		}
	}
	err := c.graphqlClient.Query(context.Background(), &query, nil)
	if err != nil {
		return "", err
	}
	return query.SharedSecrets.StorageNoncePublicKey, nil
}

type SendTransactionResponse struct {
	TransactionAddress string `json:"transaction_address"`
	Status             string
}

func (c *APIClient) SendTransaction(tx *TransactionBuilder) (SendTransactionResponse, error) {
	var response SendTransactionResponse
	jsonMap, err := tx.ToJSONMap()
	if err != nil {
		return response, err
	}
	request := map[string]interface{}{
		"transaction": jsonMap,
	}
	err = c.jsonRpcClient.CallFor(context.Background(), &response, "send_transaction", request)
	return response, err
}

func (c *APIClient) GetTransactionFee(tx *TransactionBuilder) (Fee, error) {
	var fee Fee
	jsonMap, err := tx.ToJSONMap()
	if err != nil {
		return fee, err
	}
	request := map[string]interface{}{
		"transaction": jsonMap,
	}
	err = c.jsonRpcClient.CallFor(context.Background(), &fee, "estimate_transaction_fee", request)
	return fee, err
}

type SimulateResponseError struct {
	Code    int
	Message string
	Data    map[string]interface{}
}

type SimulateResponse struct {
	RecipientAddress string `json:"recipient_address"`
	Valid            bool
	Error            SimulateResponseError
}

func (c *APIClient) SimulateContractExecution(tx *TransactionBuilder) ([]SimulateResponse, error) {
	var result []SimulateResponse
	jsonMap, err := tx.ToJSONMap()
	if err != nil {
		return result, err
	}
	request := map[string]interface{}{
		"transaction": jsonMap,
	}
	err = c.jsonRpcClient.CallFor(context.Background(), &result, "simulate_contract_execution", request)
	return result, err
}

func (c *APIClient) GetTransactionOwnerships(address string) ([]Ownership, error) {

	var query TransactionOwnershipsGQL

	variables := map[string]interface{}{
		"address": Address(address),
	}
	err := c.graphqlClient.Query(context.Background(), &query, variables)
	if err != nil {
		return nil, err
	}

	return decodeOwnerships(query.Transaction.Data.Ownerships)
}

func (c *APIClient) GetLastTransactionOwnerships(address string) ([]Ownership, error) {

	var query LastTransactionOwnershipsGQL

	variables := map[string]interface{}{
		"address": Address(address),
	}
	err := c.graphqlClient.Query(context.Background(), &query, variables)
	if err != nil {
		return nil, err
	}

	return decodeOwnerships(query.LastTransaction.Data.Ownerships)
}

func decodeOwnerships(queryOwnerships []OwnershipGQL) ([]Ownership, error) {

	ownerships := make([]Ownership, len(queryOwnerships))
	for i, ownership := range queryOwnerships {
		secret, err := hex.DecodeString(string(ownership.Secret))
		if err != nil {
			return nil, err
		}
		authorizedKeys := make([]AuthorizedKey, len(ownership.AuthorizedPublicKeys))

		for j, authorizedPublicKey := range ownership.AuthorizedPublicKeys {
			publicKey, err := hex.DecodeString(string(authorizedPublicKey.PublicKey))
			if err != nil {
				return nil, err
			}
			encryptedSecretKey, err := hex.DecodeString(string(authorizedPublicKey.EncryptedSecretKey))
			if err != nil {
				return nil, err
			}

			authorizedKeys[j] = AuthorizedKey{
				PublicKey:          publicKey,
				EncryptedSecretKey: encryptedSecretKey,
			}
		}

		ownerships[i] = Ownership{
			Secret:         secret,
			AuthorizedKeys: authorizedKeys,
		}
	}

	return ownerships, nil
}

func (c *APIClient) GetToken(address string) (Token, error) {

	var query struct {
		Token TokenGQL `graphql:"token(address: $address)"`
	}

	variables := map[string]interface{}{
		"address": Address(address),
	}
	err := c.graphqlClient.Query(context.Background(), &query, variables)
	if err != nil {
		return Token{}, err
	}

	genesisAddress, err := hex.DecodeString(string(query.Token.Genesis))
	if err != nil {
		return Token{}, err
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
	}, nil

}

func (c *APIClient) AddOriginKey(originPublicKey, certificate string) (SendTransactionResponse, error) {
	input := map[string]string{
		"origin_public_key": originPublicKey,
		"certificate":       certificate,
	}
	var res SendTransactionResponse
	err := c.jsonRpcClient.CallFor(context.Background(), &res, "add_origin_key", input)
	return res, err
}

func (c *APIClient) GetOracleData(timestamp ...int64) (OracleData, error) {

	if timestamp == nil {

		var query struct{ OracleData OracleData }
		err := c.graphqlClient.Query(context.Background(), &query, nil)
		if err != nil {
			return OracleData{}, err
		}

		return query.OracleData, nil

	} else {

		var query struct {
			OracleData OracleData `graphql:"oracleData(timestamp: $timestamp)"`
		}
		variables := map[string]interface{}{
			"timestamp": Timestamp(timestamp[0]),
		}
		err := c.graphqlClient.Query(context.Background(), &query, variables)
		if err != nil {
			return OracleData{}, err
		}
		return query.OracleData, nil
	}
}

func (c *APIClient) GetBalance(address string) (Balance, error) {

	var query struct {
		Balance BalanceGQL `graphql:"balance(address: $address)"`
	}

	variables := map[string]interface{}{
		"address": Address(address),
	}
	err := c.graphqlClient.Query(context.Background(), &query, variables)
	if err != nil {
		return Balance{}, err
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
			return Balance{}, err
		}
		tokens[i].Amount = token.Amount
		tokens[i].TokenId = token.TokenId
	}
	return Balance{
		Uco:   query.Balance.Uco,
		Token: tokens,
	}, nil
}

func (c *APIClient) SubscribeToOracleUpdates(handler func(OracleData)) {
	query := `subscription{
				oracleUpdate{
					services{
						uco {eur usd}
					}
					timestamp
				}
			}`
	subscription := new(AbsintheSubscription)
	subscription.GraphqlSubscription(c.wsUrl, query, nil, nil, func(data map[string]interface{}) error {
		var response struct {
			OracleUpdate OracleData
		}

		jsonStr, err := json.Marshal(data)
		if err != nil {
			return err
		}

		if err := json.Unmarshal(jsonStr, &response); err != nil {
			return err
		}

		handler(response.OracleUpdate)
		return nil
	})
}
