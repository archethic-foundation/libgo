package archethic

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestSerializeTypedDataInt(t *testing.T) {
	b, _ := SerializeTypedData(10)
	val, _, _ := DeserializeTypedData(b)
	if val != 10 {
		t.Errorf("Expect serialization of int of 10")
	}

	b, _ = SerializeTypedData(0)
	val, _, _ = DeserializeTypedData(b)
	if val != 0 {
		t.Errorf("Expect serialization of int of 0")
	}

	b, _ = SerializeTypedData(-10)
	val, _, _ = DeserializeTypedData(b)
	if val != -10 {
		t.Errorf("Expect serialization of int of -10")
	}

	b, _ = SerializeTypedData(1000)
	val, _, _ = DeserializeTypedData(b)
	if val != 1000 {
		t.Errorf("Expect serialization of int of 1000")
	}

	b, _ = SerializeTypedData(-1000)
	val, _, _ = DeserializeTypedData(b)
	if val != -1000 {
		t.Errorf("Expect serialization of int of -1000")
	}

	b, _ = SerializeTypedData(100000000)
	val, _, _ = DeserializeTypedData(b)
	if val != 100000000 {
		t.Errorf("Expect serialization of int of 100000000")
	}

	b, _ = SerializeTypedData(-100000000)
	val, _, _ = DeserializeTypedData(b)
	if val != -100000000 {
		t.Errorf("Expect serialization of int of -100000000")
	}

	var value json.Number = "1"
	b, _ = SerializeTypedData(value)
	val, _, _ = DeserializeTypedData(b)
	if val != 1 {
		t.Errorf("Expect serialization of int of 1")
	}

	value = "-1"
	b, _ = SerializeTypedData(value)
	val, _, _ = DeserializeTypedData(b)
	if val != -1 {
		t.Errorf("Expect serialization of int of -1")
	}
}

func TestSerializeTypedDataFloat(t *testing.T) {
	b, _ := SerializeTypedData(10.5)
	val, _, _ := DeserializeTypedData(b)
	if val != 10.5 {
		t.Errorf("Expect serialization of float of 10.5")
	}

	b, _ = SerializeTypedData(-10.5)
	val, _, _ = DeserializeTypedData(b)
	if val != -10.5 {
		t.Errorf("Expect serialization of float of -10.5")
	}

	b, _ = SerializeTypedData(1000.5020)
	val, _, _ = DeserializeTypedData(b)
	if val != 1000.5020 {
		t.Errorf("Expect serialization of float of 1000.5020")
	}

	b, _ = SerializeTypedData(-1000.5020)
	val, _, _ = DeserializeTypedData(b)
	if val != -1000.5020 {
		t.Errorf("Expect serialization of float of -1000.5020")
	}

	b, _ = SerializeTypedData(100000000.249204902904)
	val, _, _ = DeserializeTypedData(b)
	if val != 100000000.249204902904 {
		t.Errorf("Expect serialization of int of 100000000.249204902904")
	}

	b, _ = SerializeTypedData(-100000000.249204902904)
	val, _, _ = DeserializeTypedData(b)
	if val != -100000000.249204902904 {
		t.Errorf("Expect serialization of float of -100000000.249204902904")
	}

	var value json.Number = "1.0"
	b, _ = SerializeTypedData(value)
	val, _, _ = DeserializeTypedData(b)
	if val != 1.0 {
		t.Errorf("Expect serialization of float of 1.0")
	}

	value = "-1.0"
	b, _ = SerializeTypedData(value)
	val, _, _ = DeserializeTypedData(b)
	if val != -1.0 {
		t.Errorf("Expect serialization of float of -1.0")
	}
}

func TestSerializeTypedDataString(t *testing.T) {
	b, _ := SerializeTypedData("hello")
	val, _, _ := DeserializeTypedData(b)
	if val != "hello" {
		t.Errorf("Expect serialization of string 'hello'")
	}

	b, _ = SerializeTypedData("")
	val, _, _ = DeserializeTypedData(b)
	if val != "" {
		t.Errorf("Expect serialization of string '' ")
	}

	b, _ = SerializeTypedData("78")
	val, _, _ = DeserializeTypedData(b)
	if val != "78" {
		t.Errorf("Expect serialization of string '78' ")
	}

	b, _ = SerializeTypedData("78.0")
	val, _, _ = DeserializeTypedData(b)
	if val != "78.0" {
		t.Errorf("Expect serialization of string '78.0' ")
	}
}

func TestSerializeTypedDataList(t *testing.T) {
	list := []string{"hello"}
	b, _ := SerializeTypedData(list)
	val, _, _ := DeserializeTypedData(b)

	interfaceSlice := convertToInterfaceSlice(val)
	convertedSlice := make([]string, len(interfaceSlice))
	for i, v := range interfaceSlice {
		convertedSlice[i] = v.(string)
	}

	if !reflect.DeepEqual(list, convertedSlice) {
		t.Errorf("Expect serialization of list ['hello']")
	}

	list2 := createUntypedSlice()
	b2, _ := SerializeTypedData(list2)
	val2, _, _ := DeserializeTypedData(b2)

	if !reflect.DeepEqual(list2, val2) {
		t.Errorf("Expect serialization of list ['hello']")
	}
}

func TestSerializeTypedDataMap(t *testing.T) {
	m := map[string]string{
		"hello": "a",
	}

	b, _ := SerializeTypedData(m)
	mapValue, _, _ := DeserializeTypedData(b)

	if inputMap, ok := mapValue.(map[string]interface{}); ok {
		result := make(map[string]string)
		for key, value := range inputMap {
			// Check if the value is a string
			if strValue, ok := value.(string); ok {
				result[key] = strValue
			}
		}

		if !reflect.DeepEqual(result, m) {
			t.Errorf("Expect serialization of map['hello']:'a'")
		}
	}
}

func TestSerializeTypedDataBool(t *testing.T) {
	b, _ := SerializeTypedData(true)
	res, _, _ := DeserializeTypedData(b)

	if res == false {
		t.Errorf("Expect serialization of `true`")
	}

	b, _ = SerializeTypedData(false)
	res, _, _ = DeserializeTypedData(b)

	if res == true {
		t.Errorf("Expect serialization of `false`")
	}
}

func TestSerializeTypedDataNil(t *testing.T) {
	b, _ := SerializeTypedData(nil)
	res, _, _ := DeserializeTypedData(b)

	if res != nil {
		t.Errorf("Expect serialization of `nil`")
	}
}

func convertToInterfaceSlice(input interface{}) []interface{} {
	// Check if the input is already a []interface{}
	if result, ok := input.([]interface{}); ok {
		return result
	}

	// Check if the input is a slice
	if slice, ok := input.([]interface{}); ok {
		return slice
	}

	// Create a new []interface{} slice
	result := make([]interface{}, 0)

	// Handle other types
	switch v := input.(type) {
	case []string:
		for _, item := range v {
			result = append(result, item)
		}
	case []int:
		for _, item := range v {
			result = append(result, item)
		}
	// Add more cases for other types as needed

	default:
		// Handle unsupported types or return an empty slice
	}

	return result
}

func createUntypedSlice() []any {
	buf := make([]any, 0)

	buf = append(buf, 1)
	buf = append(buf, "hello")
	buf = append(buf, 2.59)
	buf = append(buf, true)

	return buf
}
