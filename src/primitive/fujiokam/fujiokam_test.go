package fujiokam

import (
	"testing"
	"math/big"
)

func TestDecomposeThreeSquare(t *testing.T) {
	x := new(big.Int).SetInt64(42)
	a, b, d := decomposeThreeSquare(x)
	if a.Int64() != 0 || b.Int64() != 5 || d.Int64() != 12 {
		t.Error("Decomposition failed")
	}
}

func TestCreation(t *testing.T) {
	createBase()
}

func TestNonneg(t *testing.T) {
	base := createBase()
	x := new(big.Int).SetInt64(100)
	commitx, rc := base.Commit(x)
	commitrx, C, Cr, R, x_, a_, b_, d_, r_ := base.ProveNonneg(x, commitx, rc)
	res := base.VerifyNonneg(commitx, commitrx, C, Cr, R, x_, a_, b_, d_, r_)
	if !res {
		t.Error("Verification failed")
	}
}