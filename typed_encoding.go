package archethic

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"sort"
)

type EncodedType uint8

const (
	IntegerType EncodedType = 0
	FloatType   EncodedType = 1
	StringType  EncodedType = 2
	ListType    EncodedType = 3
	MapType     EncodedType = 4
	BoolType    EncodedType = 5
	NilType     EncodedType = 6
)

func SerializeTypedData(val interface{}) ([]byte, error) {
	rVal := reflect.ValueOf(val)
	switch rVal.Kind() {
	case reflect.Int:
		return serializeInt(val.(int)), nil
	case reflect.Float64:
		return serializeFloat(val.(float64)), nil
	case reflect.String:
		jsonNumber, err := getJsonNumber(rVal)
		if err == nil {
			// jsonNumber may either be int or float
			integer, err := jsonNumber.Int64()
			if err == nil {
				return serializeInt(int(integer)), nil
			}

			float, err := jsonNumber.Float64()
			if err == nil {
				return serializeFloat(float), nil
			}
		}
		return serializeString(val.(string)), nil
	case reflect.Map:
		keys := make([]string, 0)
		m := make(map[string]interface{}, 0)

		for _, key := range rVal.MapKeys() {
			switch k := key.Interface().(type) {
			case string:
				m[k] = rVal.MapIndex(key).Interface()
				keys = append(keys, k)
			default:
				return nil, fmt.Errorf("map's key can only be string")
			}
		}

		sort.Strings(keys)
		return serializeMap(keys, m)
	case reflect.Slice:
		// Create a new []interface{} slice
		convertedSlice := make([]interface{}, rVal.Len())

		// Iterate over the elements of the slice
		for i := 0; i < rVal.Len(); i++ {
			// Perform a type conversion for each element
			convertedSlice[i] = rVal.Index(i).Interface()
		}

		return serializeList(convertedSlice)
	case reflect.Bool:
		return serializeBool(val.(bool)), nil
	case reflect.Invalid:
		return []byte{byte(NilType)}, nil
	default:
		return nil, fmt.Errorf("unsupported type %s", reflect.TypeOf(val))
	}
}

func serializeInt(number int) []byte {
	signBit := signToBit[int](number)
	abs := int(math.Abs(float64(number)))
	encodedVarInt := EncodeVarInt(uint64(abs))

	buf := make([]byte, 0)
	buf = append(buf, byte(IntegerType))
	buf = append(buf, byte(signBit))
	buf = append(buf, encodedVarInt...)

	return buf
}

func serializeFloat(number float64) []byte {
	signBit := signToBit[float64](number)
	abs := math.Abs(float64(number))
	encodedVarInt := EncodeVarInt(ToBigInt(abs))

	buf := make([]byte, 0)
	buf = append(buf, byte(FloatType))
	buf = append(buf, byte(signBit))
	buf = append(buf, encodedVarInt...)

	return buf
}

func serializeString(data string) []byte {
	size := len(data)
	varIntEncoded := EncodeVarInt(uint64(size))

	buf := make([]byte, 0)
	buf = append(buf, byte(StringType))
	buf = append(buf, varIntEncoded...)
	buf = append(buf, data...)

	return buf
}

func serializeList(data []any) ([]byte, error) {
	size := len(data)
	varIntEncoded := EncodeVarInt(uint64(size))

	buf := make([]byte, 0)
	buf = append(buf, byte(ListType))
	buf = append(buf, varIntEncoded...)

	for i := 0; i < size; i++ {
		bytes, err := SerializeTypedData(data[i])
		if err != nil {
			return nil, err
		}
		buf = append(buf, bytes...)
	}

	return buf, nil
}

func serializeMap(sortedKeys []string, data map[string]interface{}) ([]byte, error) {
	size := len(sortedKeys)

	varIntEncoded := EncodeVarInt(uint64(size))

	buf := make([]byte, 0)
	buf = append(buf, byte(MapType))
	buf = append(buf, varIntEncoded...)
	for _, key := range sortedKeys {
		k_bytes, err := SerializeTypedData(key)
		if err != nil {
			return nil, err
		}

		v := data[key]
		v_bytes, err := SerializeTypedData(v)
		if err != nil {
			return nil, err
		}

		buf = append(buf, k_bytes...)
		buf = append(buf, v_bytes...)
	}

	return buf, nil
}

func serializeBool(data bool) []byte {
	var boolByte byte
	if data {
		boolByte = byte(1)
	} else {
		boolByte = byte(0)
	}

	buf := make([]byte, 0)
	buf = append(buf, byte(BoolType))
	buf = append(buf, boolByte)

	return buf
}

func DeserializeTypedData(bin []byte) (any, []byte, error) {
	var data = bin[1:]

	switch bin[0] {
	case byte(IntegerType):
		return deserializeInt(data)
	case byte(FloatType):
		return deserializeFloat(data)
	case byte(StringType):
		return deserializeString(data)
	case byte(ListType):
		return deserializeList(data)
	case byte(MapType):
		return deserializeMap(data)
	case byte(BoolType):
		return deserializeBool(data)
	case byte(NilType):
		return nil, data, nil
	default:
		return nil, nil, fmt.Errorf("unsupported argument type: %d", bin[0])
	}
}

func deserializeInt(data []byte) (int, []byte, error) {
	var signBit = data[0]
	var signFactor = bitToSign(uint(signBit))
	number, remaning_bytes := DecodeVarInt(data[1:])
	return int(number) * signFactor, remaning_bytes, nil
}

func deserializeFloat(data []byte) (float64, []byte, error) {
	var signBit = data[0]
	var signFactor = bitToSign(uint(signBit))
	number, remaning_bytes := DecodeVarInt(data[1:])

	return FromBigInt(number) * float64(signFactor), remaning_bytes, nil
}

func deserializeString(data []byte) (string, []byte, error) {
	str_size, remaning_bytes := DecodeVarInt(data)
	str := remaning_bytes[:str_size]
	return string(str), remaning_bytes[str_size:], nil
}

func deserializeList(data []byte) ([]any, []byte, error) {
	var _remaining_bytes []byte
	list_size, remaining_bytes := DecodeVarInt(data)
	buf := make([]any, 0)

	_remaining_bytes = remaining_bytes

	for i := 0; i < int(list_size); i++ {
		data, remaining_bytes, err := DeserializeTypedData(_remaining_bytes)
		if err != nil {
			return nil, nil, err
		}
		_remaining_bytes = remaining_bytes
		buf = append(buf, data)
	}
	return buf, _remaining_bytes, nil
}

func deserializeMap(data []byte) (map[string]any, []byte, error) {
	var _remaining_bytes []byte
	map_size, remaining_bytes := DecodeVarInt(data)
	buf := map[string]any{}

	_remaining_bytes = remaining_bytes

	for i := 0; i < int(map_size); i++ {
		key_data, remaining_bytes, err := DeserializeTypedData(_remaining_bytes)
		if err != nil {
			return nil, nil, err
		}
		_remaining_bytes = remaining_bytes

		value_data, remaining_bytes, err := DeserializeTypedData(_remaining_bytes)
		if err != nil {
			return nil, nil, err
		}
		_remaining_bytes = remaining_bytes

		v := reflect.ValueOf(key_data)
		switch v.Kind() {
		case reflect.String:
			buf[key_data.(string)] = value_data
		default:
			return nil, nil, fmt.Errorf("key's type %s is not supported", v.Kind())
		}
	}

	return buf, _remaining_bytes, nil
}

func deserializeBool(data []byte) (bool, []byte, error) {
	var res bool
	switch data[0] {
	case byte(1):
		res = true
	case byte(0):
		res = false
	default:
		return false, nil, fmt.Errorf("unsupported byte %x to deserialize bool", data[0])
	}
	return res, data[1:], nil
}

func signToBit[T int | float64](x T) uint {
	if x >= 0 {
		return 1
	} else {
		return 0
	}
}

func bitToSign(x uint) int {
	if x == 0 {
		return -1
	} else {
		return 1
	}
}

func getJsonNumber(rVal reflect.Value) (number json.Number, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("not a number")
		}
	}()
	number = rVal.Interface().(json.Number)
	return number, nil
}
