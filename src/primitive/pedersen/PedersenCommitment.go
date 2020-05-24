package pedersen
import (
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/random"
	"github.com/dedis/crypto/nist"
)

type PedersenBase struct {
	Suite abstract.Suite
	HT abstract.Point
	GT abstract.Point
}

func CreateBase() *PedersenBase {
	suite := nist.NewAES128SHA256QR512()
	return CreateBaseFromSuite(suite)
}

// initialize h with g
func CreateMinimalBaseFromSuite(suite abstract.Suite) *PedersenBase {
	h := suite.Point().Mul(nil, suite.Secret().One())
	g := suite.Point().Mul(nil, suite.Secret().One())
	base := &PedersenBase {
		Suite: suite,
		HT: h,
		GT: g,
	}
	return base
}

// initialize h with g^s, where s is a random number
func CreateBaseFromSuite(suite abstract.Suite) *PedersenBase {
	s := suite.Secret().Pick(random.Stream)
	h := suite.Point().Mul(nil, s)
	g := suite.Point().Mul(nil, suite.Secret().One())
	base := &PedersenBase {
		Suite: suite,
		HT: h,
		GT: g,
	}
	return base
}

type Commitment abstract.Point

// Commit to a secret x.
// Generate random number r, then compute pcomm = g^x * h^r
func (base *PedersenBase) Commit(x abstract.Secret) (Commitment, abstract.Secret) {
	// Ideally, r should be chosen from Z_{p-1}. But here:
	// Order of r is either (p-1) when r is odd, or (p-1)/2 when r is even.
	// Both are large enough.
	r := base.Suite.Secret().Pick(random.Stream)
	pcomm := base.CommitWithR(x, r)
	return pcomm, r
}

// compute g^x * h^r (mod p)
func (base *PedersenBase) CommitWithR(x, r abstract.Secret) Commitment {
	t1 := base.Suite.Point().Mul(base.GT, x)
	t2 := base.Suite.Point().Mul(base.HT, r)
	pcomm := base.Suite.Point().Add(t1, t2)
	return pcomm
}

// randomize a commitment c: c^E
func (base *PedersenBase) Randomize(c abstract.Point) (abstract.Point, abstract.Secret) {
	E := base.Suite.Secret().Pick(random.Stream)
	// HE := base.Suite.Point().Mul(base.HT, E)
	// return base.Suite.Point().Add(c, HE), E
	return base.Suite.Point().Mul(c, E), E
}

func (base *PedersenBase) Add(x, y Commitment) Commitment {
	return base.Suite.Point().Add(x, y);
}

func (base *PedersenBase) Sub(x, y Commitment) Commitment {
	return base.Suite.Point().Sub(x, y);
}

// Verify pcomm == g^x * h^r
func (base *PedersenBase) Verify(x abstract.Secret, r abstract.Secret, pcomm Commitment) bool {
	t1 := base.Suite.Point().Mul(base.GT, x)
	t2 := base.Suite.Point().Mul(base.HT, r)
	res := base.Suite.Point().Add(t1, t2)
	return res.Equal(pcomm)
}