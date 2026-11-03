package dstu4145

import (
	"errors"
	"fmt"
	"math/big"
	"sync"
)

// A Curve is one of the DSTU 4145-2002 named curves y^2 + xy = x^3 + ax^2 + b
// over GF(2^m) with a base point of prime order n. Curves are immutable and
// safe for concurrent use.
type Curve struct {
	f field
	a *big.Int // 0 or 1
	b *big.Int
	n *big.Int
	g point
}

// point is an affine point; x == nil is the point at infinity.
type point struct{ x, y *big.Int }

func (p point) isInfinity() bool { return p.x == nil }

// namedCurves are the curves of DSTU 4145-2002 Annex Б as Bouncy Castle
// defines them in DSTU4145NamedCurves; the index is the last arc of the OID.
var namedCurves = sync.OnceValue(func() [10]*Curve {
	curve := func(f field, a int64, b, n, gx, gy string) *Curve {
		return &Curve{f: f, a: big.NewInt(a), b: hexInt(b), n: hexInt(n), g: point{hexInt(gx), hexInt(gy)}}
	}
	return [10]*Curve{
		curve(newField(163, 3, 6, 7), 1, "5FF6108462A2DC8210AB403925E638A19C1455D21", "400000000000000000002BEC12BE2262D39BCF14D",
			"2E2F85F5DD74CE983A5C4237229DAF8A3F35823BE", "3826F008A8C51D7B95284D9D03FF0E00CE2CD723A"),
		curve(newField(167, 6), 1, "6EE3CEEB230811759F20518A0930F1A4315A827DAC", "3FFFFFFFFFFFFFFFFFFFFFB12EBCC7D7F29FF7701F",
			"7A1F6653786A68192803910A3D30B2A2018B21CD54", "5F49EB26781C0EC6B8909156D98ED435E45FD59918"),
		curve(newField(173, 1, 2, 10), 0, "108576C80499DB2FC16EDDF6853BBB278F6B6FB437D9", "800000000000000000000189B4E67606E3825BB2831",
			"4D41A619BCC6EADF0448FA22FAD567A9181D37389CA", "10B51CC12849B234C75E6DD2028BF7FF5C1CE0D991A1"),
		curve(newField(179, 1, 2, 4), 1, "4A6E0856526436F2F88DD07A341E32D04184572BEB710", "3FFFFFFFFFFFFFFFFFFFFFFB981960435FE5AB64236EF",
			"6BA06FE51464B2BD26DC57F48819BA9954667022C7D03", "25FBC363582DCEC065080CA8287AAFF09788A66DC3A9E"),
		curve(newField(191, 9), 1, "7BC86E2102902EC4D5890E8B6B4981ff27E0482750FEFC03", "40000000000000000000000069A779CAC1DABC6788F7474F",
			"714114B762F2FF4A7912A6D2AC58B9B5C2FCFE76DAEB7129", "29C41E568B77C617EFE5902F11DB96FA9613CD8D03DB08DA"),
		curve(newField(233, 1, 4, 9), 1, "06973B15095675534C7CF7E64A21BD54EF5DD3B8A0326AA936ECE454D2C", "1000000000000000000000000000013E974E72F8A6922031D2603CFE0D7",
			"3FCDA526B6CDF83BA1118DF35B3C31761D3545F32728D003EEB25EFE96", "9CA8B57A934C54DEEDA9E54A7BBAD95E3B2E91C54D32BE0B9DF96D8D35"),
		curve(newField(257, 12), 0, "1CEF494720115657E18F938D7A7942394FF9425C1458C57861F9EEA6ADBE3BE10", "800000000000000000000000000000006759213AF182E987D3E17714907D470D",
			"02A29EF207D0E9B6C55CD260B306C7E007AC491CA1B10C62334A9E8DCD8D20FB7", "10686D41FF744D4449FCCF6D8EEA03102E6812C93A9D60B978B702CF156D814EF"),
		curve(newField(307, 2, 4, 8), 1, "393C7F7D53666B5054B5E6C6D3DE94F4296C0C599E2E2E241050DF18B6090BDC90186904968BB", "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC079C2F3825DA70D390FBBA588D4604022B7B7",
			"216EE8B189D291A0224984C1E92F1D16BF75CCD825A087A239B276D3167743C52C02D6E7232AA", "5D9306BACD22B7FAEB09D2E049C6E2866C5D1677762A8F2F2DC9A11C7F7BE8340AB2237C7F2A0"),
		curve(newField(367, 21), 1, "43FC8AD242B0B7A6F3D1627AD5654447556B47BF6AA4A64B0C2AFE42CADAB8F93D92394C79A79755437B56995136", "40000000000000000000000000000000000000000000009C300B75A3FA824F22428FD28CE8812245EF44049B2D49",
			"324A6EDDD512F08C49A99AE0D3F961197A76413E7BE81A400CA681E09639B5FE12E59A109F78BF4A373541B3B9A1", "1AB597A5B4477F59E39539007C7F977D1A567B92B043A49C6B61984C3FE3481AAF454CD41BA1F051626442B3C10"),
		curve(newField(431, 1, 3, 5), 1, "03CE10490F6A708FC26DFE8C3D27C4F94E690134D5BFF988D8D28AAEAEDE975936C66BAC536B18AE2DC312CA493117DAA469C640CAF3", "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBA3175458009A8C0A724F02F81AA8A1FCBAF80D90C7A95110504CF",
			"1A62BA79D98133A16BBAE7ED9A8E03C32E0824D57AEF72F88986874E5AAE49C27BED49A2A95058068426C2171E99FD3B43C5947C857D", "70B5E1E14031C1F70BBEFE96BDDE66F451754B4CA5F48DA241F331AA396B8D1839A855C1769B1EA14BA53308B5E2723724E090E02DB9"),
	}
})

func hexInt(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("dstu4145: bad curve constant " + s)
	}
	return v
}

// NamedCurve returns the DSTU 4145-2002 named curve with the given number,
// the last arc of its OID 1.2.804.2.1.1.1.1.3.1.1.2.id. The numbers and field
// sizes m are: 0 — 163, 1 — 167, 2 — 173, 3 — 179, 4 — 191, 5 — 233,
// 6 — 257 (M257, the curve of Ukrainian qualified certificates), 7 — 307,
// 8 — 367, 9 — 431.
func NamedCurve(id int) (*Curve, error) {
	curves := namedCurves()
	if id < 0 || id >= len(curves) {
		return nil, fmt.Errorf("dstu4145: unknown named curve %d", id)
	}
	return curves[id], nil
}

// CurveParams are the explicit parameters of a curve as certificates carry
// them in DSTU4145ECBinary.
type CurveParams struct {
	M int      // degree of the field GF(2^m)
	K []int    // middle exponents of the reduction polynomial: one for a trinomial, three for a pentanomial
	A int      // coefficient a, 0 or 1
	B *big.Int // coefficient b
	N *big.Int // order of the base point
	G []byte   // base point in the compressed encoding of PublicKey.Bytes
}

// CurveFromParams returns the named curve with parameters p. Only the ten
// named curves are supported: any other curve is an error.
func CurveFromParams(p CurveParams) (*Curve, error) {
	if p.B == nil || p.N == nil {
		return nil, errors.New("dstu4145: curve parameters lack b or n")
	}
	poly := newField(p.M, p.K...).poly
	g := new(big.Int).SetBytes(p.G)
	for _, c := range namedCurves() {
		if c.f.poly.Cmp(poly) == 0 && c.a.Cmp(big.NewInt(int64(p.A))) == 0 && c.b.Cmp(p.B) == 0 && c.n.Cmp(p.N) == 0 &&
			new(big.Int).SetBytes((&PublicKey{curve: c, q: c.g}).Bytes()).Cmp(g) == 0 {
			return c, nil
		}
	}
	return nil, fmt.Errorf("dstu4145: the curve over GF(2^%d) is not one of the named curves", p.M)
}

// Order returns a copy of n, the order of the curve base point.
func (c *Curve) Order() *big.Int { return new(big.Int).Set(c.n) }

func (c *Curve) isOnCurve(p point) bool {
	f := c.f
	lhs := f.add(f.sqr(p.y), f.mul(p.x, p.y))
	x2 := f.sqr(p.x)
	rhs := f.add(f.add(f.mul(x2, p.x), f.mul(c.a, x2)), c.b)
	return lhs.Cmp(rhs) == 0
}

func (c *Curve) neg(p point) point {
	if p.isInfinity() {
		return p
	}
	return point{p.x, c.f.add(p.x, p.y)}
}

func (c *Curve) double(p point) point {
	if p.isInfinity() || p.x.Sign() == 0 {
		return point{}
	}
	f := c.f
	lambda := f.add(p.x, f.mul(p.y, f.inv(p.x)))
	x := f.add(f.add(f.sqr(lambda), lambda), c.a)
	y := f.add(f.mul(f.addOne(lambda), x), f.sqr(p.x))
	return point{x, y}
}

func (c *Curve) add(p, q point) point {
	switch {
	case p.isInfinity():
		return q
	case q.isInfinity():
		return p
	case p.x.Cmp(q.x) == 0:
		if p.y.Cmp(q.y) == 0 {
			return c.double(p)
		}
		return point{} // q = -p
	}
	f := c.f
	sx := f.add(p.x, q.x)
	lambda := f.mul(f.add(p.y, q.y), f.inv(sx))
	x := f.add(f.add(f.add(f.sqr(lambda), lambda), sx), c.a)
	y := f.add(f.add(f.mul(lambda, f.add(p.x, x)), x), p.y)
	return point{x, y}
}

// scalarMult is left-to-right double-and-add. It is not constant-time.
func (c *Curve) scalarMult(p point, k *big.Int) point {
	r := point{}
	for i := k.BitLen() - 1; i >= 0; i-- {
		r = c.double(r)
		if k.Bit(i) == 1 {
			r = c.add(r, p)
		}
	}
	return r
}
