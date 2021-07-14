package pedersen_fujiokam

import (
	"math/big"
	"testing"

	"zRep/primitive/fujiokam"
	"zRep/primitive/pedersen"
)

func TestEqual(t *testing.T) {
	pedersenBase := pedersen.CreateBase()
	fujiokamBase := fujiokam.CreateBase()
	xRaw := new(big.Int).SetInt64(10)
	x := pedersenBase.Suite.Secret().SetInt64(10)
	PComm, rPComm := pedersenBase.Commit(x)
	FOComm, rFOComm := fujiokamBase.Commit(xRaw)
	arg := ProveEqual(pedersenBase, fujiokamBase, x, PComm, rPComm, FOComm, rFOComm)
	res := VerifyEqual(pedersenBase, fujiokamBase, PComm, FOComm, arg)
	if res != true {
		t.Error("Verify failed")
	}
}

func TestBigIntToSecret(t *testing.T) {
	i := new(big.Int).SetInt64(42)
	pedersenBase := pedersen.CreateBase()
	suite := pedersenBase.Suite
	s := BigIntToSecret(suite, i)
	if s.String() != "2a" {
		t.Error("42(dec) should become 2a(hex)")
	}
}