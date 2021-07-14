package fujiokam

import (
	"github.com/dedis/crypto/abstract"
	"crypto/cipher"
	"errors"
	"math/big"
	"io"
	"github.com/dedis/crypto/random"
	"github.com/dedis/crypto/group"
	"github.com/dedis/crypto/nist"
)

var one = big.NewInt(1)

type residuePoint struct {
	big.Int
	g *ResidueGroup
}

// Steal value from DSA, which uses recommendation from FIPS 186-3
const numMRTests = 64

// Probabilistically test whether a big integer is prime.
func isPrime(i *big.Int) bool {
	return i.ProbablyPrime(numMRTests)
}

func (p *residuePoint) String() string { return p.Int.String() }

func (p *residuePoint) Equal(p2 abstract.Point) bool {
	return p.Int.Cmp(&p2.(*residuePoint).Int) == 0
}

func (p *residuePoint) Null() abstract.Point {
	p.Int.SetInt64(1)
	return p
}

func (p *residuePoint) Base() abstract.Point {
	p.Int.Set(p.g.G)
	return p
}

func (p *residuePoint) Valid() bool {
	return p.Int.Sign() > 0 && p.Int.Cmp(p.g.P) < 0 &&
		new(big.Int).Exp(&p.Int, p.g.Q, p.g.P).Cmp(one) == 0
}

func (p *residuePoint) PickLen() int {
	// Reserve at least 8 most-significant bits for randomness,
	// and the least-significant 16 bits for embedded data length.
	return (p.g.P.BitLen() - 8 - 16) / 8
}

// Pick a point containing a variable amount of embedded data.
// Remaining bits comprising the point are chosen randomly.
// This will only work efficiently for quadratic residue groups!
func (p *residuePoint) Pick(data []byte, rand cipher.Stream) (abstract.Point, []byte) {

	l := p.g.PointLen()
	dl := p.PickLen()
	if dl > len(data) {
		dl = len(data)
	}

	for {
		b := random.Bits(uint(p.g.P.BitLen()), false, rand)
		if data != nil {
			b[l-1] = byte(dl) // Encode length in low 16 bits
			b[l-2] = byte(dl >> 8)
			copy(b[l-dl-2:l-2], data) // Copy in embedded data
		}
		p.Int.SetBytes(b)
		if p.Valid() {
			return p, data[dl:]
		}
	}
}

// Extract embedded data from a Residue group element
func (p *residuePoint) Data() ([]byte, error) {
	b := p.Int.Bytes()
	l := p.g.PointLen()
	if len(b) < l { // pad leading zero bytes if necessary
		b = append(make([]byte, l-len(b)), b...)
	}
	dl := int(b[l-2])<<8 + int(b[l-1])
	if dl > p.PickLen() {
		return nil, errors.New("invalid embedded data length")
	}
	return b[l-dl-2 : l-2], nil
}

func (p *residuePoint) Add(a, b abstract.Point) abstract.Point {
	p.Int.Mul(&a.(*residuePoint).Int, &b.(*residuePoint).Int)
	p.Int.Mod(&p.Int, p.g.P)
	return p
}

func (p *residuePoint) Sub(a, b abstract.Point) abstract.Point {
	binv := new(big.Int).ModInverse(&b.(*residuePoint).Int, p.g.P)
	p.Int.Mul(&a.(*residuePoint).Int, binv)
	p.Int.Mod(&p.Int, p.g.P)
	return p
}

func (p *residuePoint) Neg(a abstract.Point) abstract.Point {
	p.Int.ModInverse(&a.(*residuePoint).Int, p.g.P)
	return p
}

func (p *residuePoint) Mul(b abstract.Point, s abstract.Secret) abstract.Point {
	if b == nil {
		return p.Base().Mul(p, s)
	}
	p.Int.Exp(&b.(*residuePoint).Int, &s.(*nist.Int).V, p.g.P)
	return p
}

func (p *residuePoint) MarshalSize() int {
	return (p.g.P.BitLen() + 7) / 8
}

func (p *residuePoint) MarshalBinary() ([]byte, error) {
	b := p.Int.Bytes() // may be shorter than len(buf)
	if pre := p.MarshalSize() - len(b); pre != 0 {
		return append(make([]byte, pre), b...), nil
	}
	return b, nil
}

func (p *residuePoint) UnmarshalBinary(data []byte) error {
	p.Int.SetBytes(data)
	if !p.Valid() {
		return errors.New("invalid Residue group element")
	}
	return nil
}

func (p *residuePoint) MarshalTo(w io.Writer) (int, error) {
	return group.PointMarshalTo(p, w)
}

func (p *residuePoint) UnmarshalFrom(r io.Reader) (int, error) {
	return group.PointUnmarshalFrom(p, r)
}

type ResidueGroup struct {
	P *big.Int
	Q *big.Int
	G *big.Int
	R *big.Int
}

func (g *ResidueGroup) PointLen() int { return (g.P.BitLen() + 7) / 8 }
