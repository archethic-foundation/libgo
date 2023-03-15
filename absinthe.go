package archethic

import (
	"log"
	"net/url"

	"github.com/nshafer/phx"
)

type AbsintheSubscription struct {
	socket *phx.Socket
	ref    phx.Ref
}

func (a *AbsintheSubscription) GraphqlSubscription(wsUrl, query string, variables map[string]string, readyHandler func(), handler func(map[string]interface{})) {
	endPoint, _ := url.Parse(wsUrl)

	// Create a new phx.Socket
	socket := phx.NewSocket(endPoint)
	a.socket = socket

	// Wait for the socket to connect before continuing. If it's not able to, it will keep
	// retrying forever.
	cont := make(chan bool)
	a.ref = socket.OnOpen(func() {
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

func (a *AbsintheSubscription) CancelSubscription() {
	a.socket.Off(a.ref)
}
