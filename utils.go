package archethic

import (
	"encoding/hex"
	"errors"
	"math/big"
	"regexp"
)

func OriginPrivateKey() []byte {
	originPrivateKey, _ := hex.DecodeString("01019280BDB84B8F8AEDBA205FE3552689964A5626EE2C60AA10E3BF22A91A036009")
	return originPrivateKey
}

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

func ParseBigInt(number string, formatDecimals uint) (*big.Int, error) {
	r := regexp.MustCompile(`^([0-9]*)\.?([0-9]*)$`)
	matches := r.FindAllStringSubmatch(number, -1)
	if len(matches) == 0 || len(matches[0]) == 0 || len(matches[0][1])+len(matches[0][2]) == 0 {
		return nil, errors.New("Invalid number")
	}

	wholeStr := matches[0][1]
	decimalStr := matches[0][2]

	// Pad out the decimals
	for len(decimalStr) < int(formatDecimals) {
		decimalStr += "0000"
	}

	// Remove extra padding
	decimalStr = decimalStr[:formatDecimals]

	b, _ := new(big.Int).SetString(wholeStr+decimalStr, 10)

	return b, nil
}

func FormatBigInt(b *big.Int, formatDecimals uint8) string {
	strNumber := b.String()
	if formatDecimals == 0 {
		return strNumber
	}

	// Pad out to the whole component (including a whole digit)
	for len(strNumber) <= int(formatDecimals) {
		strNumber = "0000" + strNumber
	}

	// Insert the decimal point
	index := len(strNumber) - int(formatDecimals)
	strNumber = strNumber[:index] + "." + strNumber[index:]

	// Trim the whole component (leaving at least one 0)
	for strNumber[0] == '0' && strNumber[1] != '.' {
		strNumber = strNumber[1:]
	}

	// Trim the decimal component (leaving at least one 0)
	for strNumber[len(strNumber)-1] == '0' && strNumber[len(strNumber)-2] != '.' {
		strNumber = strNumber[:len(strNumber)-1]
	}

	return strNumber
}
