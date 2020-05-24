package pedersen_fujiokam

import (
	"../pedersen"
	"../fujiokam"
	"math/big"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/random"
	"github.com/dedis/crypto/nist"
	// "fmt"
)

type ARGequal struct {
	C *big.Int
	S1 *big.Int
	S2 *big.Int
	S3 *big.Int
}

// transform abstract.Secret (implemented by nist.Int) to *big.Int
func SecretToBigInt(s abstract.Secret) *big.Int {
	return &s.(*nist.Int).V
}

// transform *big.Int to abstract.Secret (implemented by nist.Int)
func BigIntToSecret(suite abstract.Suite, i *big.Int) abstract.Secret {
	s := suite.Secret()
	nistS := s.(*nist.Int)
	nistS.V.Mod(i, nistS.M)
	return s
}

func ProveEqual(pedersenBase *pedersen.PedersenBase, fujiokamBase *fujiokam.FujiOkamBase,
	x abstract.Secret,
	PComm abstract.Point, rPComm abstract.Secret,
	FOComm *fujiokam.Point, rFOComm *big.Int) *ARGequal {
	suite := pedersenBase.Suite
	t1 := suite.Secret().Pick(random.Stream)
	t1Raw := SecretToBigInt(t1)
	t2 := suite.Secret().Pick(random.Stream)
	t2Raw := SecretToBigInt(t2)
	t3 := suite.Secret().Pick(random.Stream)
	t3Raw := SecretToBigInt(t3)
	// T1 := GT^t1 * HT^t2 (mod p)
	T1 := pedersenBase.CommitWithR(t1, t2)
	byteT1, _ := T1.MarshalBinary()

	// T2 := g1^t1 * h1^t3 (mod n)
	T2 := fujiokamBase.CommitWithR(t1Raw, t3Raw)
	byteT2 := T2.ToBinary()

	// c := hash(T1 || T2)
	hash := suite.Hash()
	hash.Write(byteT1)
	hash.Write(byteT2)
	cBuf := hash.Sum(nil)
	cRaw := new(big.Int)
	cRaw.SetBytes(cBuf)

	xRaw := SecretToBigInt(x)
	rPCommRaw := SecretToBigInt(rPComm)
	// s1 := x*c + t1
	s1 := new(big.Int)
	s1.Mul(xRaw, cRaw).Add(s1, t1Raw)
	// s2 := rPComm*c + t2
	s2 := new(big.Int)
	s2.Mul(rPCommRaw, cRaw).Add(s2, t2Raw)
	// s3 := rFOComm*c + t3
	s3 := new(big.Int)
	s3.Mul(rFOComm, cRaw).Add(s3, t3Raw)

	return &ARGequal{
		C: cRaw,
		S1: s1,
		S2: s2,
		S3: s3,
	}
}

func VerifyEqual(pedersenBase *pedersen.PedersenBase, fujiokamBase *fujiokam.FujiOkamBase,
	PComm abstract.Point, FOComm *fujiokam.Point, arg *ARGequal) bool {
	s1 := BigIntToSecret(pedersenBase.Suite, arg.S1)
	s2 := BigIntToSecret(pedersenBase.Suite, arg.S2)
	c := BigIntToSecret(pedersenBase.Suite, arg.C)
	negC := pedersenBase.Suite.Secret().Neg(c)
	negCRaw := new(big.Int).Neg(arg.C)

	// T1 := GT^s1 * HT^s2 * PComm^(-c) mod p
	T1 := pedersenBase.CommitWithR(s1, s2)
	tmp := pedersenBase.Suite.Point().Mul(PComm, negC)
	T1.Add(T1, tmp)
	byteT1, _ := T1.MarshalBinary()

	// T2 := g1^s1 * h1^s3 * FOComm^(-c) mod n
	T2 := fujiokamBase.CommitWithR(arg.S1, arg.S3)
	tmp2 := fujiokamBase.Point().Exp(FOComm, negCRaw)
	T2.Mul(T2, tmp2)
	byteT2 := T2.ToBinary()

	// c := hash(T1 || T2)
	hash := pedersenBase.Suite.Hash()
	hash.Write(byteT1)
	hash.Write(byteT2)
	RSideBuf := hash.Sum(nil)
	RSide := new(big.Int)
	RSide.SetBytes(RSideBuf)

	return arg.C.Cmp(RSide) == 0
}