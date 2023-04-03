package archethic

import (
	"encoding/hex"
	"regexp"
)

// MaybeConvertToHex converts a string to a byte array if it is a hex string,
// otherwise it returns the string as a byte array
func MaybeConvertToHex(inputString string) []byte {
	if isHex(inputString) {
		value, err := hex.DecodeString(inputString)
		if err != nil {
			panic(err)
		}
		return value
	}
	return []byte(inputString)
}

func isHex(inputString string) bool {
	re := regexp.MustCompile("^[0-9A-Fa-f]*$")
	return re.MatchString(inputString)
}
