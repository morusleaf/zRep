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

func TestGnHonestyProof(t *testing.T) {
	// server generate
	base := CreateBase()
	secrets := make([]*big.Int, GN_HONESTY_PROOF_SIZE)
	publics := make([]*Point, GN_HONESTY_PROOF_SIZE)
	base.GenerateGnHonestyProof(secrets, publics)

	// client generates bits
	bits := make([]bool, GN_HONESTY_PROOF_SIZE)
	base.ChallengeGnHonesty(bits)

	// server answers
	answers := make([]*big.Int, GN_HONESTY_PROOF_SIZE)
	base.AnswerGnHonesty(bits, secrets, base.alpha1, answers)

	// clients checks
	if !base.CheckGnHonesty(answers, bits, publics, base.G1) {
		t.Error("Check failed")
	}
}

func TestAllGnHonestyProof(t *testing.T) {
	// server generate
	base := CreateBase()
	secrets, publics := base.GenerateAllGnHonestyProof()

	// client generates bits
	challenges := base.ChallengeAllGnHonesty()

	// server answers
	answers := base.AnswerAllGnHonesty(challenges, secrets, publics)

	// clients checks
	if res := base.CheckAllGnHonesty(answers, challenges, publics); res != 0 {
		t.Error("Check failed on", res)
	}
}
