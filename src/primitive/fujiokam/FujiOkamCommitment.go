package fujiokam
import (
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/random"
	"github.com/dedis/crypto/nist"
	"math/big"
	"math"
	"crypto/sha256"
)

type FujiOkamBase struct {
	Suite abstract.Suite
	G1 *Point
	G2 *Point
	G3 *Point
	G4 *Point
	G5 *Point
	G6 *Point
	H1 *Point
	N *big.Int
	RandomRadius *big.Int
	RandomDiameter *big.Int
	P *big.Int // only one side knows P and Q
	Q *big.Int
}

// genRandomSecret returns a random int from -RandomRadius ~ RandomRadius,
// and it has be in Z*_{p*q}
func (base *FujiOkamBase) genRandomSecret() *big.Int {
	// p := base.P
	// q := base.Q
	// pq := new(big.Int).Mul(p, q)
	// var s *big.Int = nil
	// modp := new(big.Int)
	// modq := new(big.Int)
	// for {
	// 	s = random.Int(base.RandomDiameter, random.Stream)
	// 	s.Sub(s, base.RandomRadius)
	// 	alpha := new(big.Int).Mod(s, pq)
	// 	// (alpha, p) = 1 and (alpha, q) = 1 and alpha != 1
	// 	if alpha.Cmp(bigOne) == 0 {
	// 		continue
	// 	}
	// 	modp.Mod(alpha, p)
	// 	if modp.Cmp(bigZero) == 0 {
	// 		continue
	// 	}
	// 	modq.Mod(alpha, q)
	// 	if modq.Cmp(bigZero) == 0 {
	// 		continue
	// 	}
	// 	break
	// }
	// return s
	s := random.Int(base.RandomDiameter, random.Stream)
	s.Sub(s, base.RandomRadius)
	return s
}

// genGn returns a random gn from <H1>
func (base *FujiOkamBase) genGn() *Point {
	alpha := base.genRandomSecret()
	Gn := base.Point().Exp(base.H1, alpha)
	return Gn
}

// genH returns a random int from Z*_n
func (base *FujiOkamBase) genH() *Point {
	p := base.P
	q := base.Q
	dpPlusOne := new(big.Int).Add(p, p)
	dpPlusOne.Add(dpPlusOne, bigOne)
	dqPlusOne := new(big.Int).Add(q, q)
	dqPlusOne.Add(dqPlusOne, bigOne)
	modRes := new(big.Int)
	var h1 *big.Int = nil
	for {
		h1 = random.Int(base.N, random.Stream)
		if h1.Cmp(bigOne) == 0 {
			continue
		}
		modRes.Mod(h1, dpPlusOne)
		if modRes.Cmp(bigZero) == 0 {
			continue
		}
		modRes.Mod(h1, dqPlusOne)
		if modRes.Cmp(bigZero) == 0 {
			continue
		}
		break
	}
	H1 := base.Point().BigInt(h1)
	H1.Mul(H1, H1)
	return H1
}

func CreateMinimumBase(suite abstract.Suite, n *big.Int) (*FujiOkamBase) {
	base := &FujiOkamBase {
		Suite : suite,
		N : n,
	}
	randomRadius, _ := new(big.Int).SetString("10000", 16)
	randomRadius.Mul(randomRadius, base.N)
	randomDiameter := new(big.Int).Mul(randomRadius, bigTwo)
	base.RandomRadius = randomRadius
	base.RandomDiameter = randomDiameter
	return base
}

func CreateBase() (*FujiOkamBase) {
	suite := nist.NewAES128SHA256QR512()
	return CreateBaseFromSuite(suite)
}

func CreateBaseFromSuite(suite abstract.Suite) (*FujiOkamBase) {
	p := new(big.Int).SetInt64(3)
	q := new(big.Int).SetInt64(5)
	// n := (2p + 1) * (2q + 1)
	n := new(big.Int).SetInt64(77)
	base := CreateMinimumBase(suite, n)
	base.P = p
	base.Q = q
	
	base.H1 = base.genH()
	base.G1 = base.genGn()
	base.G2 = base.genGn()
	base.G3 = base.genGn()
	base.G4 = base.genGn()
	base.G5 = base.genGn()
	base.G6 = base.genGn()

	return base
}

// Decompose 4x+1 into sum of three squares.
// In other words, find a, b and d, such that 4x+1 = a^2 + b^2 + d^2
// Reference: Legendre's three-square theorem
func decomposeThreeSquareHelper(x int64) (int64, int64, int64) {
	var goal int64 = 4*x+1
	var bound int64 = int64(math.Sqrt(float64(goal)))
	var a, b, d int64
	for a = 0; a <= bound; a++ {
		aa := a * a
		for b = 0; b <= bound; b++ {
			bb := b * b
			if aa + bb > goal {
				continue
			}
			for d = 0; d < bound; d++ {
				dd := d * d
				if aa + bb + dd == goal {
					return a, b, d
				}
			}
		}
	}
	// Should never reach here
	panic(1)
}

func decomposeThreeSquare(x *big.Int) (*big.Int, *big.Int, *big.Int) {
	a, b, d := decomposeThreeSquareHelper(x.Int64())
	return big.NewInt(a), big.NewInt(b), big.NewInt(d)
}

var bigZero = big.NewInt(0)
var bigOne = big.NewInt(1)
var bigTwo = big.NewInt(2)
var bigFour = big.NewInt(4)
var bigRange = big.NewInt(1000)
var bigNegOne = big.NewInt(-1)

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

func (p *Point) BigInt(a *big.Int) *Point {
	p.V = *a
	return p
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

func (base *FujiOkamBase) Commit(x *big.Int) (*Point, *big.Int) {
	r := base.genRandomSecret()
	commitx := base.Point().Exp(base.G1, x)
	tp := base.Point().Exp(base.H1, r)
	commitx.Mul(commitx, tp)
	return commitx, r
}

type ARGnonneg struct {
	Commitrx *big.Int
	C *big.Int
	Cr *big.Int
	R *big.Int
	X_ *big.Int
	A_ *big.Int
	B_ *big.Int
	D_ *big.Int
	R_ *big.Int
}

func (base*FujiOkamBase) ProveNonneg(x *big.Int, commitx *Point, rc *big.Int) *ARGnonneg {
	commitrx, C, Cr, R, x_, a_, b_, d_, r_ := base.ProveNonnegHelper(x, commitx, rc)
	return &ARGnonneg{
		Commitrx: &commitrx.V,
		C: &C.V,
		Cr: &Cr.V,
		R: R,
		X_: x_,
		A_: a_,
		B_: b_,
		D_: d_,
		R_: r_,
	}
}

func (base *FujiOkamBase) ProveNonnegHelper(x *big.Int, commitx *Point, rc *big.Int) (*Point, *Point, *Point, *big.Int, *big.Int, *big.Int, *big.Int, *big.Int, *big.Int) {
	if x.Cmp(bigZero) < 0 {
		panic("x must be non-negative");
	}
	a, b, d := decomposeThreeSquare(x)
	ti := new(big.Int)
	tp := base.Point()
	// rx, ra, rb, rd := random
	rx := base.genRandomSecret()
	ra := base.genRandomSecret()
	rb := base.genRandomSecret()
	rd := base.genRandomSecret()
	// delta := 4*rx - 2*a*ra - 2*b*rb - 2*d*rd
	delta := new(big.Int)
	delta.Mul(bigFour, rx)
	ti.Mul(bigTwo, a).Mul(ti, ra)
	delta.Sub(delta, ti)
	ti.Mul(bigTwo, b).Mul(ti, rb)
	delta.Sub(delta, ti)
	ti.Mul(bigTwo, d).Mul(ti, rd)
	delta.Sub(delta, ti)
	// r := random
	r := base.genRandomSecret()
	// C := g2^x * g3^a * g4^b * g5^d * g6^delta * h^r (mod n)
	C := base.Point()
	C.Exp(base.G2, x)
	tp.Exp(base.G3, a)
	C.Mul(C, tp)
	tp.Exp(base.G4, b)
	C.Mul(C, tp)
	tp.Exp(base.G5, d)
	C.Mul(C, tp)
	tp.Exp(base.G6, delta)
	C.Mul(C, tp)
	tp.Exp(base.H1, r)
	C.Mul(C, tp)
	// rr := random
	rr := base.genRandomSecret()
	// Cr := g2^rx * g3^rx * g3^ra * g4^rb * g5^rd * g6^(-ra^2-rb^2-rd^2) * h^rr (mod n)
	Cr := base.Point()
	Cr.Exp(base.G2, rx)
	tp.Exp(base.G3, ra)
	Cr.Mul(Cr, tp)
	tp.Exp(base.G4, rb)
	Cr.Mul(Cr, tp)
	tp.Exp(base.G5, rd)
	Cr.Mul(Cr, tp)
	ti.Mul(ra, ra).Neg(ti)
	tp.Exp(base.G6, ti)
	Cr.Mul(Cr, tp)
	ti.Mul(rb, rb).Neg(ti)
	tp.Exp(base.G6, ti)
	Cr.Mul(Cr, tp)
	ti.Mul(rd, rd).Neg(ti)
	tp.Exp(base.G6, ti)
	Cr.Mul(Cr, tp)
	tp.Exp(base.H1, rr)
	Cr.Mul(Cr, tp)
	ti.SetInt64(-1)
	tp.Exp(base.G6, ti)
	// commitrx = g^rx * h^rrx (mod n)
	commitrx, rrx := base.Commit(rx)
	// e = hash(commitx, C, Cr)
	h := sha256.New()
	h.Write(commitx.V.Bytes())
	h.Write(C.V.Bytes())
	h.Write(Cr.V.Bytes())
	eBuf := h.Sum(nil)
	e := new(big.Int)
	e.SetBytes(eBuf)
	// x' := xe + rx
	x_ := new(big.Int)
	x_.Mul(x, e).Add(x_, rx)
	// a' := a*e + ra
	a_ := new(big.Int)
	a_.Mul(a, e)
	a_.Add(a_, ra)
	// b' := b*e + rb
	b_ := new(big.Int)
	b_.Mul(b, e).Add(b_, rb)
	// d' := d*e + rd
	d_ := new(big.Int)
	d_.Mul(d, e).Add(d_, rd)
	// r' := r*e + rr
	r_ := new(big.Int)
	r_.Mul(r, e).Add(r_, rr)
	// R := e*rx + rrx
	R := new(big.Int)
	R.Mul(e, rc).Add(R, rrx)
	return commitrx, C, Cr, R, x_, a_, b_, d_, r_
}

func (base *FujiOkamBase) VerifyNonneg(commitx *Point, arg *ARGnonneg) bool {
	commitrx := base.Point().BigInt(arg.Commitrx)
	C := base.Point().BigInt(arg.C)
	Cr := base.Point().BigInt(arg.Cr)
	return base.VerifyNonnegHelper(commitx, commitrx, C, Cr, arg.R, arg.X_, arg.A_, arg.B_, arg.D_, arg.R_)
}

func (base *FujiOkamBase) VerifyNonnegHelper(commitx, commitrx, C, Cr *Point, R, x_, a_, b_, d_, r_ *big.Int) bool {
	// e := hash(commitx, C, Cr)
	h := sha256.New()
	h.Write(commitx.V.Bytes())
	h.Write(C.V.Bytes())
	h.Write(Cr.V.Bytes())
	eBuf := h.Sum(nil)
	e := new(big.Int)
	e.SetBytes(eBuf)
	// delta' := e*(4*x' + e) - a'^2 - b'^2 - d'^2
	delta_ := new(big.Int)
	ti := new(big.Int)
	ti.Mul(bigFour, x_).Add(ti, e)
	delta_.Mul(e, ti)
	ti.Mul(a_, a_)
	delta_.Sub(delta_, ti)
	ti.Mul(b_, b_)
	delta_.Sub(delta_, ti)
	ti.Mul(d_, d_)
	delta_.Sub(delta_, ti)

	// Lside := C^e * Cr (mod n)
	Lside := base.Point()
	Lside.Exp(C, e).Mul(Lside, Cr)
	// Rside := g2^x' * g3^a' * g4^b' * g5^d' * g6^delta' * h^r' (mod n)
	Rside := base.Point()
	Rside.Exp(base.G2, x_)
	tp := base.Point()
	tp.Exp(base.G3, a_)
	Rside.Mul(Rside, tp)
	tp.Exp(base.G4, b_)
	Rside.Mul(Rside, tp)
	tp.Exp(base.G5, d_)
	Rside.Mul(Rside, tp)
	tp.Exp(base.G6, delta_)
	Rside.Mul(Rside, tp)
	tp.Exp(base.H1, r_)
	Rside.Mul(Rside, tp)
	// check Lside == Rside
	if !Lside.Equal(Rside) {
		return false
	}

	// Lside := commitx^e * commitrx
	Lside.Exp(commitx, e)
	Lside.Mul(Lside, commitrx)
	// Rside := g^x' * h^R
	Rside.Exp(base.G1, x_)
	tp.Exp(base.H1, R)
	Rside.Mul(Rside, tp)
	// check Lside == Rside
	if !Lside.Equal(Rside) {
		return false
	}

	return true
}