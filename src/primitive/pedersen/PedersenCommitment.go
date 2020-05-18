package pedersen
import (
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/random"
	"github.com/dedis/crypto/nist"
)

type PedersenBase struct {
	Suite abstract.Suite
	H abstract.Point
}

func createBase() *PedersenBase {
	suite := nist.NewAES128SHA256QR512()
	s := suite.Secret().Pick(random.Stream)
	h := suite.Point().Mul(nil, s)
	base := &PedersenBase {
		Suite: suite,
		H: h}
	return base
}

type Commitment abstract.Point

// Commit to a secret x.
// Generate random number r, then compute pcomm = g^x * h^r
func (pedersen *PedersenBase) Commit(x abstract.Secret) (Commitment, abstract.Secret) {
	// Ideally, r should be chosen from Z_{p-1}. But here:
	// Order of r is either (p-1) when r is odd, or (p-1)/2 when r is even.
	// Both are large enough.
	r := pedersen.Suite.Secret().Pick(random.Stream)
	t1 := pedersen.Suite.Point().Mul(nil, x)
	t2 := pedersen.Suite.Point().Mul(pedersen.H, r)
	pcomm := pedersen.Suite.Point().Add(t1, t2)
	return pcomm, r
}

func (pedersen *PedersenBase) Add(x, y Commitment) Commitment {
	return pedersen.Suite.Point().Add(x, y);
}

func (pedersen *PedersenBase) Sub(x, y Commitment) Commitment {
	return pedersen.Suite.Point().Sub(x, y);
}

// Verify pcomm == g^x * h^r
func (pedersen *PedersenBase) Verify(x abstract.Secret, r abstract.Secret, pcomm Commitment) bool {
	t1 := pedersen.Suite.Point().Mul(nil, x)
	t2 := pedersen.Suite.Point().Mul(pedersen.H, r)
	res := pedersen.Suite.Point().Add(t1, t2)
	return res.Equal(pcomm)
}