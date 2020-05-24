package lrs

import (
	"testing"
	"math/big"
	// "fmt"
)

func TestSign(t *testing.T) {
	g := new(big.Int).SetInt64(4)
	base := CreateBase(g)

	text := "hello world"
	m := []byte(text)
	n := 2

	x := make([]*big.Int, n)
	y := make([]*big.Int, n)
	for i, _ := range x {
		x[i] = base.pickZq()
		y[i] = new(big.Int).Exp(base.G, x[i], base.P)
	}
	sig := base.SignHelper(m, n, 0, x[0], y)

	if base.VerifyHelper(m, n, 0, sig, y) != true {
		t.Error("verification failed")
	}
}

func TestLinkable(t *testing.T) {
	g := new(big.Int).SetInt64(4)
	base := CreateBase(g)

	text := "hello world"
	m := []byte(text)
	n := 2

	x := make([]*big.Int, n)
	y := make([]*big.Int, n)
	for i, _ := range x {
		x[i] = base.pickZq()
		y[i] = new(big.Int).Exp(base.G, x[i], base.P)
	}
	sig1 := base.SignHelper(m, n, 0, x[0], y)
	sig2 := base.SignHelper(m, n, 0, x[0], y)

	if sig1.Y0.Cmp(sig2.Y0) != 0{
		t.Error("Two signatures' Y0 should have been equal")
	}
}

func TestEncoding(t *testing.T) {
	g := new(big.Int).SetInt64(4)
	base := CreateBase(g)

	text := "hello world"
	m := []byte(text)
	n := 2

	x := make([]*big.Int, n)
	y := make([]*big.Int, n)
	for i, _ := range x {
		x[i] = base.pickZq()
		y[i] = new(big.Int).Exp(base.G, x[i], base.P)
	}
	sig := base.SignHelper(m, n, 0, x[0], y)

	bytes := ProtobufEncodeSignature(sig)
	sig2 := ProtobufDecodeSignature(bytes)

	if base.VerifyHelper(m, n, 0, sig2, y) != true {
		t.Error("verification failed")
	}
}