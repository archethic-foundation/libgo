package archethic

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"sync"
	"time"
)

const senderContext = "SENDER"

type TransactionSender struct {
	client                           *APIClient
	onSent                           []func()
	onConfirmation                   []func(nbConfirmations, maxConfirmations int)
	onFullConfirmation               []func(maxConfirmations int)
	onRequiredConfirmation           []func(nbConfirmations int)
	onError                          []func(senderContext, message string)
	onTimeout                        []func(nbConfirmationReceived int)
	nbConfirmationReceived           int
	timeout                          *Timeout
	transactionErrorSubscription     *AbsintheSubscription
	transactionConfirmedSubscription *AbsintheSubscription
}

func NewTransactionSender(client *APIClient) TransactionSender {
	return TransactionSender{
		client,
		[]func(){},
		[]func(nbConfirmations, maxConfirmations int){},
		[]func(maxConfirmations int){},
		[]func(nbConfirmations int){},
		[]func(senderContext, message string){},
		[]func(nbConfirmationReceived int){},
		0,
		nil,
		nil,
		nil,
	}
}

func (ts *TransactionSender) AddOnSent(handler func()) {
	ts.onSent = append(ts.onSent, handler)
}

func (ts *TransactionSender) AddOnConfirmation(handler func(nbConfirmations, maxConfirmations int)) {
	ts.onConfirmation = append(ts.onConfirmation, handler)
}

func (ts *TransactionSender) AddOnFullConfirmation(handler func(maxConfirmations int)) {
	ts.onFullConfirmation = append(ts.onFullConfirmation, handler)
}

func (ts *TransactionSender) AddOnRequiredConfirmation(handler func(nbConfirmations int)) {
	ts.onRequiredConfirmation = append(ts.onRequiredConfirmation, handler)
}

func (ts *TransactionSender) AddOnError(handler func(senderContext, message string)) {
	ts.onError = append(ts.onError, handler)
}

func (ts *TransactionSender) AddOnTimeout(handler func(nbConfirmationReceived int)) {
	ts.onTimeout = append(ts.onTimeout, handler)
}

func (ts *TransactionSender) Unsubscribe(event string) {
	if event != "" {
		switch event {
		case "sent":
			ts.onSent = []func(){}
		case "confirmation":
			ts.onConfirmation = []func(nbConfirmations, maxConfirmations int){}
		case "requiredConfirmation":
			ts.onRequiredConfirmation = []func(nbConfirmations int){}
		case "fullConfirmation":
			ts.onFullConfirmation = []func(maxConfirmations int){}
		case "error":
			ts.onError = []func(senderContext string, message string){}
		case "timeout":
			ts.onTimeout = []func(nbConfirmationReceived int){}
		default:
			panic(fmt.Sprintf("Event %s is not supported", event))
		}
	} else {
		ts.transactionErrorSubscription.CancelSubscription()
		ts.transactionConfirmedSubscription.CancelSubscription()
		ts.onSent = []func(){}
		ts.onConfirmation = []func(nbConfirmations, maxConfirmations int){}
		ts.onRequiredConfirmation = []func(nbConfirmations int){}
		ts.onFullConfirmation = []func(maxConfirmations int){}
		ts.onError = []func(senderContext string, message string){}
		ts.onTimeout = []func(nbConfirmationReceived int){}
	}
}

func (ts *TransactionSender) SendTransaction(tx *TransactionBuilder, confirmationThreshold, timeout int) {

	done := make(chan bool)
	var wg sync.WaitGroup
	wg.Add(2)

	transactionAddress := hex.EncodeToString(tx.Address)

	go ts.SubscribeTransactionConfirmed(transactionAddress, func() {
		wg.Done()
	}, func(transactionConfirmed TransactionConfirmedGQL) {
		log.Println("Transaction is confirmed")
		log.Println(transactionConfirmed)
		if ts.handleConfirmation(confirmationThreshold, transactionConfirmed.NbConfirmations, transactionConfirmed.MaxConfirmations) {
			done <- true
		}
	})

	go ts.SubscribeTransactionError(transactionAddress, func() {
		wg.Done()
	}, func(transactionError TransactionErrorGQL) {
		log.Println("Error during transaction")
		log.Println(transactionError)
		ts.handleError(string(transactionError.Context), transactionError.Reason)
		done <- true
	})

	wg.Wait()

	payload, err := tx.ToJSON()
	if err != nil {
		panic(err)
	}
	transactionUrl := ts.client.baseURL + "/transaction"
	req, err := http.NewRequest("POST", transactionUrl, bytes.NewReader(payload))
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := ts.client.httpClient.Do(req)
	if err != nil {
		panic(err)
	}
	go ts.handleSend(timeout, resp, func(isFinished bool) {
		if isFinished {
			done <- true
		}
	})

	<-done
}

func (ts *TransactionSender) SubscribeTransactionError(transactionAddress string, readyHandler func(), handler func(TransactionErrorGQL)) {

	query := `subscription ($address: Address!){
		transactionError(address: $address) {
			context
			reason
		}
	}`
	variables := make(map[string]string)
	variables["address"] = transactionAddress

	ts.transactionErrorSubscription = new(AbsintheSubscription)
	ts.transactionErrorSubscription.GraphqlSubscription(ts.client.wsUrl, query, variables, readyHandler, func(data map[string]interface{}) {
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

func (ts *TransactionSender) SubscribeTransactionConfirmed(transactionAddress string, readyHandler func(), handler func(TransactionConfirmedGQL)) {

	query := `subscription ($address: Address!){
		transactionConfirmed(address: $address) {
			nbConfirmations
			maxConfirmations
		}
	}`
	variables := make(map[string]string)
	variables["address"] = transactionAddress

	ts.transactionConfirmedSubscription = new(AbsintheSubscription)
	ts.transactionConfirmedSubscription.GraphqlSubscription(ts.client.wsUrl, query, variables, readyHandler, func(data map[string]interface{}) {
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

func (ts *TransactionSender) handleConfirmation(confirmationThreshold, nbConfirmations, maxConfirmations int) bool {
	ts.nbConfirmationReceived = nbConfirmations

	if nbConfirmations == 1 {
		ts.transactionErrorSubscription.CancelSubscription()
	}

	for _, f := range ts.onConfirmation {
		f(nbConfirmations, maxConfirmations)
	}

	if maxConfirmations*(confirmationThreshold/100) <= nbConfirmations && len(ts.onRequiredConfirmation) > 0 {
		for _, f := range ts.onRequiredConfirmation {
			f(nbConfirmations)
		}
		ts.onRequiredConfirmation = []func(nbConfirmations int){}
		ts.timeout.Clear()
		return true
	}

	if nbConfirmations == maxConfirmations {
		ts.timeout.Clear()
		ts.transactionConfirmedSubscription.CancelSubscription()
		for _, f := range ts.onFullConfirmation {
			f(maxConfirmations)
		}
		return true
	}
	return false
}

func (ts *TransactionSender) handleError(context, reason string) {
	ts.timeout.Clear()
	ts.transactionErrorSubscription.CancelSubscription()
	ts.transactionConfirmedSubscription.CancelSubscription()
	for _, f := range ts.onError {
		f(senderContext, reason)
	}
}

func (ts *TransactionSender) handleSend(timeout int, response *http.Response, isFinishedHandler func(bool)) {
	respBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		panic(err)
	}
	fmt.Printf("request body: %s\n", respBody)
	if response.StatusCode >= 200 && response.StatusCode <= 299 {
		for _, f := range ts.onSent {
			f()
		}

		ts.timeout = SetTimeout(func() {
			ts.transactionErrorSubscription.CancelSubscription()
			ts.transactionConfirmedSubscription.CancelSubscription()
			for _, f := range ts.onTimeout {
				f(ts.nbConfirmationReceived)
			}
			isFinishedHandler(true)
		}, time.Duration(timeout*1000000000))

	} else {
		ts.transactionErrorSubscription.CancelSubscription()
		ts.transactionConfirmedSubscription.CancelSubscription()
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(respBody), &data); err != nil {
			panic(err)
		}

		status, ok := data["status"].(string)
		if !ok {
			status = string(respBody)
		}
		for _, f := range ts.onError {
			f(senderContext, status)
		}
		isFinishedHandler(true)
	}
}

type Timeout struct {
	callback  func()
	duration  time.Duration
	clearChan chan bool
}

func SetTimeout(callback func(), duration time.Duration) *Timeout {
	t := &Timeout{callback: callback, duration: duration, clearChan: make(chan bool)}

	go func() {
		select {
		case <-time.After(duration):
			callback()
		case <-t.clearChan:
			return
		}
	}()

	return t
}

func (t *Timeout) Clear() {
	t.clearChan <- true
}
