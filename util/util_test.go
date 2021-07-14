package util

import (
	"testing"
	"fmt"
	"github.com/dedis/crypto/random"
	"math/big"
	// "github.com/dedis/protobuf"
)

func TestBoolListEncoding(t *testing.T) {
	input := make([]bool, 10)
	for i, _ := range input {
		input[i] = random.Bool(random.Stream)
	}
	fmt.Println(input)

	data := ProtobufEncodeBoolList(input)
	fmt.Println(data)

	output := ProtobufDecodeBoolList(data)
	fmt.Println(output)
}

func TestBigIntListEncoding(t *testing.T) {
	input := make([]*big.Int, 10)
	randomRadius,_ := new(big.Int).SetString("1000000", 16)
	randomDiameter,_ := new(big.Int).SetString("2000000", 16)
	for i, _ := range input {
		n := random.Int(randomDiameter, random.Stream)
		n.Sub(n, randomRadius)
		input[i] = n
	}
	fmt.Println("input :", input)

	data := ProtobufEncodeBigIntList(input)
	fmt.Println("data  :", data)

	output := ProtobufDecodeBigIntList(data)
	fmt.Println("output:", output)

	if len(input) != len(output) {
		t.Error("Length not equal")
	}
	for i, a := range input {
		b := output[i]
		if a.Cmp(b) != 0 {
			t.Error(a, "!=", b)
		}
	}
}

func TestBigIntEncoding (t *testing.T) {
	n := new(big.Int).SetInt64(-10)
	fmt.Println(n)
	data := EncodeBigInt(n)
	m := DecodeBigInt(data)
	if n.Cmp(m) != 0 {
		t.Error(n, "!=", m)
	}
}

// func TestXXX (t *testing.T) {
// 	n := new(big.Int).SetInt64(-10)
// 	fmt.Println(n)
// 	data,err := protobuf.Encode(n)
// 	if err != nil {
// 		panic(err)
// 	}
// 	m := new(big.Int)
// 	err = protobuf.Decode(data, m)
// 	if err != nil {
// 		panic(err)
// 	}
// 	fmt.Println(m)
// }