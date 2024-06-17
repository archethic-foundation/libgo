package archethic

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

const senderContext = "SENDER"

type TransactionSender struct {
	client                           *APIClient
	onSent                           []func()
	onConfirmation                   []func(nbConfirmations, maxConfirmations uint)
	onFullConfirmation               []func(maxConfirmations uint)
	onRequiredConfirmation           []func(nbConfirmations uint)
	onError                          []func(senderContext string, error ErrorDetails)
	onTimeout                        []func(nbConfirmationReceived uint)
	nbConfirmationReceived           uint
	timeout                          *Timeout
	transactionErrorSubscription     *AbsintheSubscription
	transactionConfirmedSubscription *AbsintheSubscription
}

func NewTransactionSender(client *APIClient) *TransactionSender {
	return &TransactionSender{
		client,
		[]func(){},
		[]func(nbConfirmations, maxConfirmations uint){},
		[]func(maxConfirmations uint){},
		[]func(nbConfirmations uint){},
		[]func(senderContext string, error ErrorDetails){},
		[]func(nbConfirmationReceived uint){},
		0,
		nil,
		nil,
		nil,
	}
}

func (ts *TransactionSender) AddOnSent(handler func()) {
	ts.onSent = append(ts.onSent, handler)
}

func (ts *TransactionSender) AddOnConfirmation(handler func(nbConfirmations, maxConfirmations uint)) {
	ts.onConfirmation = append(ts.onConfirmation, handler)
}

func (ts *TransactionSender) AddOnFullConfirmation(handler func(maxConfirmations uint)) {
	ts.onFullConfirmation = append(ts.onFullConfirmation, handler)
}

func (ts *TransactionSender) AddOnRequiredConfirmation(handler func(nbConfirmations uint)) {
	ts.onRequiredConfirmation = append(ts.onRequiredConfirmation, handler)
}

func (ts *TransactionSender) AddOnError(handler func(senderContext string, error ErrorDetails)) {
	ts.onError = append(ts.onError, handler)
}

func (ts *TransactionSender) AddOnTimeout(handler func(nbConfirmationReceived uint)) {
	ts.onTimeout = append(ts.onTimeout, handler)
}

func (ts *TransactionSender) Unsubscribe(event string) error {
	if event != "" {
		switch event {
		case "sent":
			ts.onSent = []func(){}
		case "confirmation":
			ts.onConfirmation = []func(nbConfirmations, maxConfirmations uint){}
		case "requiredConfirmation":
			ts.onRequiredConfirmation = []func(nbConfirmations uint){}
		case "fullConfirmation":
			ts.onFullConfirmation = []func(maxConfirmations uint){}
		case "error":
			ts.onError = []func(senderContext string, error ErrorDetails){}
		case "timeout":
			ts.onTimeout = []func(nbConfirmationReceived uint){}
		default:
			return fmt.Errorf("event %s is not supported", event)
		}
	} else {
		ts.transactionErrorSubscription.CancelSubscription()
		ts.transactionConfirmedSubscription.CancelSubscription()
		ts.onSent = []func(){}
		ts.onConfirmation = []func(nbConfirmations, maxConfirmations uint){}
		ts.onRequiredConfirmation = []func(nbConfirmations uint){}
		ts.onFullConfirmation = []func(maxConfirmations uint){}
		ts.onError = []func(senderContext string, error ErrorDetails){}
		ts.onTimeout = []func(nbConfirmationReceived uint){}
	}
	return nil
}

func (ts *TransactionSender) SendTransaction(tx *TransactionBuilder, confirmationThreshold, timeout uint) error {

	done := make(chan bool)
	var wg sync.WaitGroup
	wg.Add(2)

	transactionAddress := hex.EncodeToString(tx.Address)

	go ts.SubscribeTransactionConfirmed(transactionAddress, func() {
		wg.Done()
	}, func(transactionConfirmed TransactionConfirmedGQL) {
		if ts.handleConfirmation(confirmationThreshold, transactionConfirmed.NbConfirmations, transactionConfirmed.MaxConfirmations) {
			done <- true
		}
	})

	go ts.SubscribeTransactionError(transactionAddress, func() {
		wg.Done()
	}, func(transactionError TransactionErrorGQL) {
		ts.handleError(string(transactionError.Context), transactionError.Error)
		done <- true
	})

	wg.Wait()

	_, err := ts.client.SendTransaction(tx)
	if err != nil {
		ts.transactionErrorSubscription.CancelSubscription()
		ts.transactionConfirmedSubscription.CancelSubscription()
		for _, f := range ts.onError {
			f(senderContext, ErrorDetails{Message: err.Error(), Code: -1})
		}
		return nil
	} else {
		go ts.handleSend(timeout, func(isFinished bool) {
			if isFinished {
				done <- true
			}
		})
	}

	<-done
	return nil
}

func (ts *TransactionSender) SubscribeTransactionError(transactionAddress string, readyHandler func(), handler func(TransactionErrorGQL)) {

	query := `subscription ($address: Address!){
		transactionError(address: $address) {
			context
			error {
				code,
				data,
				message
			}
		}
	}`
	variables := make(map[string]string)
	variables["address"] = transactionAddress

	ts.transactionErrorSubscription = new(AbsintheSubscription)
	ts.transactionErrorSubscription.GraphqlSubscription(ts.client.wsUrl, query, variables, readyHandler, func(data map[string]interface{}) error {
		var response struct {
			TransactionError TransactionErrorGQL
		}

		jsonStr, err := json.Marshal(data)
		if err != nil {
			return err
		}

		if err := json.Unmarshal(jsonStr, &response); err != nil {
			return err
		}

		handler(response.TransactionError)
		return nil
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
	ts.transactionConfirmedSubscription.GraphqlSubscription(ts.client.wsUrl, query, variables, readyHandler, func(data map[string]interface{}) error {
		var response struct {
			TransactionConfirmed TransactionConfirmedGQL
		}

		jsonStr, err := json.Marshal(data)
		if err != nil {
			return err
		}

		if err := json.Unmarshal(jsonStr, &response); err != nil {
			return err
		}

		handler(response.TransactionConfirmed)
		return nil
	})
}

func (ts *TransactionSender) handleConfirmation(confirmationThreshold, nbConfirmations, maxConfirmations uint) bool {
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
		ts.onRequiredConfirmation = []func(nbConfirmations uint){}
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

func (ts *TransactionSender) handleError(context string, error ErrorDetails) {
	ts.timeout.Clear()
	ts.transactionErrorSubscription.CancelSubscription()
	ts.transactionConfirmedSubscription.CancelSubscription()
	for _, f := range ts.onError {
		f(context, error)
	}
}

func (ts *TransactionSender) handleSend(timeout uint, isFinishedHandler func(bool)) error {

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

	return nil
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
