package archethic

import (
	"bytes"
	"compress/flate"
	"encoding/json"
	"fmt"

	"golang.org/x/exp/maps"
)

// Contract represents a WASM smart contract
type Contract struct {
	Bytecode []byte
	Manifest ContractManifest
}

// NewCompressedContract instanciates a new contract by compressing the bytecode
func NewCompressedContract(bytecode []byte, manifest ContractManifest) Contract {
	var b bytes.Buffer
	w, err := flate.NewWriter(&b, -1)
	if err != nil {
		panic(fmt.Sprintf("Cannot compress the bytecode %s", err.Error()))
	}

	w.Write(bytecode)
	w.Close()

	return Contract{
		Bytecode: b.Bytes(),
		Manifest: manifest,
	}
}

func (c Contract) toBytes() []byte {
	buf := []byte{1}
	buf = append(buf, EncodeInt32(uint32(len(c.Bytecode)))...)
	buf = append(buf, c.Bytecode...)
	buf = append(buf, c.Manifest.toBytes()...)

	return buf
}

// Actions returns the action of a contract
func (c Contract) Actions() []ContractAction {
	actions := make([]ContractAction, 0)
	for name, f := range c.Manifest.ABI.Functions {
		if f.FunctionType == Action && f.TriggerType == TriggerTransaction {
			actions = append(actions, ContractAction{
				Name:       name,
				Parameters: maps.Keys(f.Input),
			})
		}
	}

	return actions
}

// ContractAction represents an overview of the contract's action
type ContractAction struct {
	Name       string
	Parameters []string
}

// ContractManifest represents a manifest or specification of the contract used by clients & third-party
type ContractManifest struct {
	ABI         WasmABI `json:"abi"`
	UpgradeOpts `json:"upgradeOpts"`
}

func (m ContractManifest) toBytes() []byte {
	var iface map[string]interface{}

	bytes, _ := json.Marshal(m)
	json.Unmarshal(bytes, &iface)
	bytes, err := SerializeTypedData(iface)
	if err != nil {
		panic("invalid manifest")
	}
	return bytes
}

// WasmABI represents the interface to communicate with the WASM binary defining functions and state types
type WasmABI struct {
	State     map[string]string          `json:"state"`
	Functions map[string]WasmFunctionABI `json:"functions"`
}

// WasmFunctionABI represent the specification and the interface of a function
type WasmFunctionABI struct {
	FunctionType    WasmFunctionType       `json:"type"`
	TriggerType     WasmTriggerType        `json:"triggerType"`
	TriggerArgument string                 `json:"triggerArgument,omitempty"`
	Input           map[string]interface{} `json:"input"`
	Output          map[string]interface{} `json:"output"`
}

func (f WasmFunctionABI) toMap(name string) map[string]interface{} {
	return map[string]interface{}{
		"name":            name,
		"type":            f.FunctionType,
		"triggerType":     f.TriggerType,
		"triggerArgument": f.TriggerArgument,
		"input":           f.Input,
		"output":          f.Output,
	}
}

// WasmFunctionType represents the type of function
type WasmFunctionType string

// WasmTrigger represents the type of a trigger to execute the function
type WasmTriggerType string

const (
	// Action represents a function triggered by a transaction
	Action WasmFunctionType = "action"

	// PublicFunction represents a function called by anyone (readonly)
	PublicFunction WasmFunctionType = "publicFunction"
)

const (
	// TriggerTransaction represents an action triggered by a transaction
	TriggerTransaction WasmTriggerType = "transaction"

	// TriggerDateTime represents an action triggered by a datetime timestamp
	TriggerDateTime WasmTriggerType = "datetime"

	// TriggerInterval represents an action triggered by a cron interval
	TriggerInterval WasmTriggerType = "interval"

	// TriggerOracle represents an action triggered by an oracle's event
	TriggerOracle WasmTriggerType = "oracle"
)

// UpgradeOpts represents the options to allow the upgrade of the contract
type UpgradeOpts struct {
	From string `json:"from"`
}
