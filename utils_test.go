package archethic

import (
	"math"
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

	actual = DecodeVarInt([]byte{1, 0})
	expected = uint64(0)

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("actual %q, expected %q", actual, expected)
	}

	actual = DecodeVarInt([]byte{1, 255})
	expected = uint64(math.Pow(2, 8)) - 1

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("actual %q, expected %q", actual, expected)
	}

	actual = DecodeVarInt([]byte{2, 1, 0})
	expected = uint64(math.Pow(2, 8))

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("actual %q, expected %q", actual, expected)
	}

	actual = DecodeVarInt([]byte{2, 255, 255})
	expected = uint64(math.Pow(2, 16)) - 1

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("actual %q, expected %q", actual, expected)
	}

	actual = DecodeVarInt([]byte{3, 1, 0, 0})
	expected = uint64(math.Pow(2, 16))

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("actual %q, expected %q", actual, expected)
	}

	actual = DecodeVarInt([]byte{3, 255, 255, 255})
	expected = uint64(math.Pow(2, 24)) - 1

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("actual %q, expected %q", actual, expected)
	}

	actual = DecodeVarInt([]byte{4, 1, 0, 0, 0})
	expected = uint64(math.Pow(2, 24))

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("actual %q, expected %q", actual, expected)
	}

	actual = DecodeVarInt([]byte{4, 255, 255, 255, 255})
	expected = uint64(math.Pow(2, 32)) - 1

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("actual %q, expected %q", actual, expected)
	}

	actual = DecodeVarInt([]byte{5, 1, 0, 0, 0, 0})
	expected = uint64(math.Pow(2, 32))

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("actual %q, expected %q", actual, expected)
	}

	actual = DecodeVarInt([]byte{5, 255, 255, 255, 255, 255})
	expected = uint64(math.Pow(2, 40)) - 1

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("actual %q, expected %q", actual, expected)
	}

	actual = DecodeVarInt([]byte{6, 1, 0, 0, 0, 0, 0})
	expected = uint64(math.Pow(2, 40))

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("actual %q, expected %q", actual, expected)
	}
}
