package fujiokam

import (
	"testing"
	"math/big"
	"github.com/dedis/protobuf"
	"fmt"
	"encoding/gob"
	"bytes"
)

func TestDecomposeThreeSquare(t *testing.T) {
	x := new(big.Int).SetInt64(42)
	a, b, d := decomposeThreeSquare(x)
	if a.Int64() != 0 || b.Int64() != 5 || d.Int64() != 12 {
		t.Error("Decomposition failed")
	}
}

func TestCreation(t *testing.T) {
	CreateBase()
}

func TestNonneg(t *testing.T) {
	base := CreateBase()
	x := new(big.Int).SetInt64(100)
	commitx, rc := base.Commit(x)
	commitrx, C, Cr, R, x_, a_, b_, d_, r_ := base.ProveNonnegHelper(x, commitx, rc)
	res := base.VerifyNonnegHelper(commitx, commitrx, C, Cr, R, x_, a_, b_, d_, r_)
	if res == false {
		t.Error("Verification failed")
	}
}

func TestZero(t *testing.T) {
	base := CreateBase()
	x := new(big.Int).SetInt64(0)
	commitx, rc := base.Commit(x)
	commitrx, C, Cr, R, x_, a_, b_, d_, r_ := base.ProveNonnegHelper(x, commitx, rc)
	res := base.VerifyNonnegHelper(commitx, commitrx, C, Cr, R, x_, a_, b_, d_, r_)
	if res == false {
		t.Error("Verification failed")
	}
}

func ProtobufEncodeARGnonneg(arg *ARGnonneg) []byte {
	data, err := protobuf.Encode(arg)
	if err != nil {
		panic(err.Error())
	}
	return data
}

func ProtobufDecodeARGnonneg(bytes []byte) *ARGnonneg {
	arg := new(ARGnonneg)
	if err := protobuf.Decode(bytes, arg); err != nil {
		panic(1)
	}
	return arg
}

type AAA struct {
	x []byte
}

type ByteArray struct {
	Arr []byte
}

func Encode(event interface{}) []byte {
	var network bytes.Buffer
	err := gob.NewEncoder(&network).Encode(event)
	if err != nil {
		panic(err)
	}
	return network.Bytes()
}

type Event struct {
	x *big.Int
}

type ARG struct {
	X1 *big.Int
	X2 *big.Int
	X3 *big.Int
}

func TestEncodingARG(t *testing.T) {
	var network bytes.Buffer
	encoder := gob.NewEncoder(&network)
	decoder := gob.NewDecoder(&network)

	arg := &ARG {
		X1: new(big.Int).SetInt64(0),
		X2: new(big.Int).SetInt64(10),
		X3: new(big.Int).SetInt64(-5),
	}
	fmt.Println(arg.X1, arg.X2, arg.X3)
	
	err := encoder.Encode(arg)
	fmt.Println(err)
	fmt.Println(network.Bytes())

	var rcv ARG
	
	decoder.Decode(&rcv)
	fmt.Println(rcv.X1, rcv.X2, rcv.X3)
}

func TestEncoding(t *testing.T) {
	x := []int{0,1,2,3}
	fmt.Println(x)
	var network bytes.Buffer
	encoder := gob.NewEncoder(&network)
	err := encoder.Encode(x)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(network.Bytes())

	var y []int
	decoder := gob.NewDecoder(&network)
	decoder.Decode(&y)
	fmt.Println(y)
}