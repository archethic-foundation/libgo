package archethic

import (
	"encoding/hex"
	"regexp"
)

// MaybeConvertToHex converts a string to a byte array if it is a hex string,
// otherwise it returns the string as a byte array
func MaybeConvertToHex(inputString string) ([]byte, error) {
	if isHex(inputString) {
		value, err := hex.DecodeString(inputString)
		if err != nil {
			return nil, err
		}
		return value, nil
	}
	return []byte(inputString), nil
}

func isHex(inputString string) bool {
	re := regexp.MustCompile("^[0-9A-Fa-f]*$")
	return re.MatchString(inputString)
}

// EncodeVarInt converts a number into a VarInt binary
func EncodeVarInt(number uint64) []byte {
	if number == 0 {
		return []byte{1, 0}
	}

	a := []byte{}
	for number > 0 {
		a = append([]byte{byte(number & 255)}, a...)
		number = number >> 8
	}

	buf := make([]byte, 0)
	buf = append(buf, byte(len(a)))
	buf = append(buf, a...)

	return buf
}

// DecodeVarInt convert a VarInt binary into a integer
func DecodeVarInt(bytes []byte) (uint64, []byte) {
	size := bytes[0]
	data := bytes[1 : 1+int(size)]

	value := int(data[0])
	for i := 1; i < len(data); i++ {
		value = (value << 8) + int(data[i])
	}

	return uint64(value), bytes[size+1:]
}

func ToBigInt(number float64) uint64 {
	return uint64(number * float64(100000000))
}

func FromBigInt(number uint64) float64 {
	return float64(number) / 100000000
}
