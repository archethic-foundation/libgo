package archethic

import (
	"math"
	"math/big"
	"reflect"
	"testing"
)

func TestEncodeVarInt(t *testing.T) {

	var expected, actual []byte

	expected = []byte{1, 0}
	actual = EncodeVarInt(0)

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("actual %q, expected %q", actual, expected)
	}

	expected = []byte{1, 255}
	actual = EncodeVarInt(uint64(math.Pow(2, 8)) - 1)

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("actual %q, expected %q", actual, expected)
	}

	expected = []byte{2, 1, 0}
	actual = EncodeVarInt(uint64(math.Pow(2, 8)))

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("actual %q, expected %q", actual, expected)
	}

	expected = []byte{2, 255, 255}
	actual = EncodeVarInt(uint64(math.Pow(2, 16)) - 1)

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("actual %q, expected %q", actual, expected)
	}

	expected = []byte{3, 1, 0, 0}
	actual = EncodeVarInt(uint64(math.Pow(2, 16)))

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("actual %q, expected %q", actual, expected)
	}

	expected = []byte{3, 255, 255, 255}
	actual = EncodeVarInt(uint64(math.Pow(2, 24)) - 1)

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("actual %q, expected %q", actual, expected)
	}

	expected = []byte{4, 1, 0, 0, 0}
	actual = EncodeVarInt(uint64(math.Pow(2, 24)))

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("actual %q, expected %q", actual, expected)
	}

	expected = []byte{4, 255, 255, 255, 255}
	actual = EncodeVarInt(uint64(math.Pow(2, 32)) - 1)

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("actual %q, expected %q", actual, expected)
	}

	expected = []byte{5, 1, 0, 0, 0, 0}
	actual = EncodeVarInt(uint64(math.Pow(2, 32)))

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("actual %q, expected %q", actual, expected)
	}

	expected = []byte{5, 255, 255, 255, 255, 255}
	actual = EncodeVarInt(uint64(math.Pow(2, 40)) - 1)

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("actual %q, expected %q", actual, expected)
	}

	expected = []byte{6, 1, 0, 0, 0, 0, 0}
	actual = EncodeVarInt(uint64(math.Pow(2, 40)))

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("actual %q, expected %q", actual, expected)
	}
}

func TestDecodeVarInt(t *testing.T) {

	var actual, expected uint64

	actual, _ = DecodeVarInt([]byte{1, 0})
	expected = uint64(0)

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("actual %q, expected %q", actual, expected)
	}

	actual, _ = DecodeVarInt([]byte{1, 255})
	expected = uint64(math.Pow(2, 8)) - 1

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("actual %q, expected %q", actual, expected)
	}

	actual, _ = DecodeVarInt([]byte{2, 1, 0})
	expected = uint64(math.Pow(2, 8))

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("actual %q, expected %q", actual, expected)
	}

	actual, _ = DecodeVarInt([]byte{2, 255, 255})
	expected = uint64(math.Pow(2, 16)) - 1

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("actual %q, expected %q", actual, expected)
	}

	actual, _ = DecodeVarInt([]byte{3, 1, 0, 0})
	expected = uint64(math.Pow(2, 16))

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("actual %q, expected %q", actual, expected)
	}

	actual, _ = DecodeVarInt([]byte{3, 255, 255, 255})
	expected = uint64(math.Pow(2, 24)) - 1

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("actual %q, expected %q", actual, expected)
	}

	actual, _ = DecodeVarInt([]byte{4, 1, 0, 0, 0})
	expected = uint64(math.Pow(2, 24))

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("actual %q, expected %q", actual, expected)
	}

	actual, _ = DecodeVarInt([]byte{4, 255, 255, 255, 255})
	expected = uint64(math.Pow(2, 32)) - 1

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("actual %q, expected %q", actual, expected)
	}

	actual, _ = DecodeVarInt([]byte{5, 1, 0, 0, 0, 0})
	expected = uint64(math.Pow(2, 32))

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("actual %q, expected %q", actual, expected)
	}

	actual, _ = DecodeVarInt([]byte{5, 255, 255, 255, 255, 255})
	expected = uint64(math.Pow(2, 40)) - 1

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("actual %q, expected %q", actual, expected)
	}

	actual, _ = DecodeVarInt([]byte{6, 1, 0, 0, 0, 0, 0})
	expected = uint64(math.Pow(2, 40))

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("actual %q, expected %q", actual, expected)
	}
}

func TestParseBigInt(t *testing.T) {

	var expected *big.Int
	var actual *big.Int

	expected = big.NewInt(1253450000)
	actual, _ = ParseBigInt("12.5345", 8)

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("actual %q, expected %q", actual, expected)
	}

	expected = big.NewInt(12534500)
	actual, _ = ParseBigInt("12.5345", 6)

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("actual %q, expected %q", actual, expected)
	}

	expected = big.NewInt(1201396945692)
	actual, _ = ParseBigInt("120139.69456927", 7)

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("actual %q, expected %q", actual, expected)
	}

	expected = big.NewInt(9403999999)
	actual, _ = ParseBigInt("94.03999999999999", 8)

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("actual %q, expected %q", actual, expected)
	}

	expected = big.NewInt(12534500000000)
	actual, _ = ParseBigInt("125345", 8)

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("actual %q, expected %q", actual, expected)
	}
}

func TestFormatBigInt(t *testing.T) {

	var expected string
	var actual string

	actual = FormatBigInt(big.NewInt(1253450000), 8)
	expected = "12.5345"

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("actual %q, expected %q", actual, expected)
	}

	actual = FormatBigInt(big.NewInt(12534500), 6)
	expected = "12.5345"

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("actual %q, expected %q", actual, expected)
	}

	expected = FormatBigInt(big.NewInt(1201396945692), 7)
	actual = "120139.6945692"

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("actual %q, expected %q", actual, expected)
	}

	expected = FormatBigInt(big.NewInt(9403999999), 8)
	actual = "94.03999999"

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("actual %q, expected %q", actual, expected)
	}

	expected = FormatBigInt(big.NewInt(12534500000000), 8)
	actual = "125345.0"

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("actual %q, expected %q", actual, expected)
	}
}
