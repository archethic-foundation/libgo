package archethic

// import (
// 	"math"
// )

// func Serialize(x int) []byte {
// 	var signBit = signToBit(x)
// 	var abs = int(math.Abs(float64(x)))
// 	_, bytes := convertToMinimumBytes(abs)

// 	buf := make([]byte, 0)
// 	buf = append(buf, byte(0))
// 	buf = append(buf, byte(signBit))
// 	buf = append(buf, bytes...)

// 	return buf
// }

// func Deserialize(bin []byte) {

// 	var data = bin[1:]

// 	switch bin[0] {
// 	case 0:
// 		return deserializeInt(data)
// 	}
// }

// func deserializeInt(data []byte) (int, []byte) {
// 	var signBit = data[0]
// 	var signFactor = bitToSign(uint(signBit))

// }

// func signToBit(x int) uint {
// 	if x >= 0 {
// 		return 1
// 	} else {
// 		return 0
// 	}
// }

// func bitToSign(x uint) int {
// 	if x == 0 {
// 		return -1
// 	} else {
// 		return 1
// 	}
// }
