package fujiokam

import (
	"math/big"
)

type Point struct {
	V big.Int
	M *big.Int
}

func (p *Point) String() string {
	return p.V.String()
}

func (p *Point) ToBinary() []byte {
	return p.V.Bytes()
}

func (p *Point) FromBinary(data []byte) *Point {
	p.V.SetBytes(data)
	return p
}

func (base *FujiOkamBase) Point() *Point {
	p := new(Point)
	p.M = base.N
	return p
}

func PointFromN(N *big.Int) *Point {
	p := new(Point)
	p.M = N
	return p
}

func PointFromRaw(V *big.Int, N *big.Int) *Point {
	p := new(Point)
	p.V = *V
	p.M = N
	return p
}

func (p *Point) SetBigInt(a *big.Int) *Point {
	p.V = *a
	return p
}

func (p *Point) ToBigInt() *big.Int {
	return &p.V
}

func PointArrayToBigIntArray(points []*Point) []*big.Int {
	size := len(points)
	ints := make([]*big.Int, size)
	for i, p := range points {
		ints[i] = p.ToBigInt()
	}
	return ints
}

func (base *FujiOkamBase)BigIntArrayToPointArray(ints []*big.Int) []*Point {
	size := len(ints)
	points := make([]*Point, size)
	for i, n := range ints {
		points[i] = base.Point().SetBigInt(n)
	}
	return points
}

func (p *Point) Equal(p2 *Point) bool {
	return p.V.Cmp(&p2.V) == 0
}

func (p *Point) Add(a, b *Point) *Point {
	p.V.Add(&a.V, &b.V)
	p.V.Mod(&p.V, p.M)
	return p
}

func (p *Point) Sub(a, b *Point) *Point {
	p.V.Sub(&a.V, &b.V)
	p.V.Mod(&p.V, p.M)
	return p
}

func (p *Point) Mul(a *Point, b *Point) *Point {
	p.V.Mul(&a.V, &b.V)
	p.V.Mod(&p.V, p.M)
	return p
}

func (p *Point) Exp(a *Point, s *big.Int) *Point {
	p.V.Exp(&a.V, s, p.M)
	return p
}
