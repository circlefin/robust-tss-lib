// Copyright 2023 Circle
//
// This file implements proof aff-g from CGG21 Section 6.2 Figure 15.
// Tbe prover has secret input (x, y, rho, rhoy) and
// the verifier checks the proof against the statement (N0, N1, C, D, Y, X)
//  X = g^x \in G
//  Y = (1+N1)^y * rhoy^N1 mod N1^2
//  D = C^x * (1+N0)^y * rho^N0 mod N0^2
//
// The prover and verifier have auxiliary proof parameters
// Nhat (safe bi-prime) and s,t\in Z/Nhat* (Ring Pedersen parameters)
// The Verifier must generate the values (Nhat, s, t)
// while the prover generates N0, N1.

package zkproofs

import (
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/crypto/paillier"
)

const (
	AffGProofParts = 14
)

// Note: (z,u,v) are lowercase in aff-g from CGG21 Section 6.2 Figure 15.
type AffGProof struct {
	A  *big.Int        // mod N0^2
	Bx *crypto.ECPoint // |G|
	By *big.Int        // mod N1^2
	E  *big.Int        // mod Nhat
	S  *big.Int        // mod Nhat
	F  *big.Int        // mod Nhat
	T  *big.Int        // mod Nhat
	Z1 *big.Int        // ell + epsilon bits
	Z2 *big.Int        // ell' + epsilon bits
	Z3 *big.Int        // ell + epsilon + |Nhat| bits
	Z4 *big.Int        // ell' + epsilon + |Nhat| bits (z4 size depends on delta; CGG21 has a typo - delta should be in ell'+epsilon range)
	W  *big.Int        // mod N0
	Wy *big.Int        // mod N1
}

type AffGWitness struct {
	X    *big.Int
	Y    *big.Int
	Rho  *big.Int
	Rhoy *big.Int
}

type AffGStatement struct {
	Ell      *big.Int
	EllPrime *big.Int
	N0       *big.Int
	N1       *big.Int
	C        *big.Int
	D        *big.Int
	X        *crypto.ECPoint
	Y        *big.Int
}

// aff-g from CGG21 Section 6.2 Figure 15.
func NewAffGProof(wit *AffGWitness, stmt *AffGStatement, rp *RingPedersenParams) (*AffGProof, error) {
	// derive some parameters
	ec := stmt.X.Curve()
	ecpc := NewEll(stmt.Ell)
	ecpcprime := NewEll(stmt.EllPrime)

	// 1. Prover samples alpha, beta, r, ry, gamma, m, delta, mu
	alpha := common.GetRandomPositiveInt(ecpc.TwoPowEllPlusEpsilon)
	beta := common.GetRandomPositiveInt(ecpcprime.TwoPowEllPlusEpsilon)
	r := common.GetRandomPositiveInt(stmt.N0)
	ry := common.GetRandomPositiveInt(stmt.N1)
	gammaRange := new(big.Int).Mul(ecpc.TwoPowEllPlusEpsilon, rp.N)
	gamma := common.GetRandomPositiveInt(gammaRange)
	mRange := new(big.Int).Mul(ecpc.TwoPowEll, rp.N)
	m := common.GetRandomPositiveInt(mRange)
	// CGG21 appears to have a typo - says delta and mu are chosen
	// from ranges based on ell. This should be ell' as they are used with beta & y
	deltaRange := new(big.Int).Mul(ecpcprime.TwoPowEllPlusEpsilon, rp.N)
	delta := common.GetRandomPositiveInt(deltaRange)
	muRange := new(big.Int).Mul(ecpcprime.TwoPowEll, rp.N)
	mu := common.GetRandomPositiveInt(muRange)

	// A = C^alpha * (1+N0)^beta * r^N0 mod N0^2
	pkN0 := &paillier.PublicKey{N: stmt.N0}
	N02 := new(big.Int).Mul(stmt.N0, stmt.N0)
	Aprime := pkN0.EncryptWithRandomnessNoErrChk(beta, r)
	A := ATimesBToTheCModN(Aprime, stmt.C, alpha, N02)

	// Bx=g^alpha
	Bx := crypto.ScalarBaseMult(ec, alpha)

	// By = (1+N1)^beta * ry^N1 mod N1^2
	pkN1 := &paillier.PublicKey{N: stmt.N1}
	By := pkN1.EncryptWithRandomnessNoErrChk(beta, ry)

	// E = s^alpha t^gamma mod Nhat
	E := rp.Commit(alpha, gamma)
	// S = s^x t^m mod Nhat
	S := rp.Commit(wit.X, m)
	// F = s^beta t^delta mod Nhat
	F := rp.Commit(beta, delta)
	// T = s^y t^mu mod Nhat
	T := rp.Commit(wit.Y, mu)

	proof := &AffGProof{
		A:  A,
		Bx: Bx,
		By: By,
		E:  E,
		S:  S,
		F:  F,
		T:  T,
	}
	// 2. hash to get challenge
	e := proof.GetChallenge(stmt, rp)

	// 3. prover sends (z1, z2, z3)
	// z1 := alpha + e * x
	proof.Z1 = APlusBC(alpha, e, wit.X)

	// z2 = beta + e * y
	proof.Z2 = APlusBC(beta, e, wit.Y)

	// z3 = gammma + e * m
	proof.Z3 = APlusBC(gamma, e, m)

	// z4 = delta + e * mu
	proof.Z4 = APlusBC(delta, e, mu)

	// w = r * rho^e mod N0
	proof.W = ATimesBToTheCModN(r, wit.Rho, e, stmt.N0)

	// wy = ry * rhoy^e mod N1
	proof.Wy = ATimesBToTheCModN(ry, wit.Rhoy, e, stmt.N1)

	return proof, nil
}

// aff-g from CGG21 Section 6.2 Figure 15.
// The Verifier checks the proof against the statement (N0, C, X)
func (proof *AffGProof) Verify(stmt *AffGStatement, rp *RingPedersenParams) bool {
	if proof == nil {
		return false
	}

	if stmt.N0.Sign() != 1 && stmt.N1.Sign() != 1 {
		return false
	}

	// derive some parameters
	ec := stmt.X.Curve()

	// hash to get challenge
	e := proof.GetChallenge(stmt, rp)

    // otherwise first verification equation trivially true
    if IsZero(proof.A) || IsZero(proof.W) {
        return false
    }

	// check C^z1 (1+n0)^z2 w^N0 == A * D^e mod No^2A
	N02 := new(big.Int).Mul(stmt.N0, stmt.N0)
	pkN0 := &paillier.PublicKey{N: stmt.N0}
	encZ2 := pkN0.EncryptWithRandomnessNoErrChk(proof.Z2, proof.W)
	left1 := ATimesBToTheCModN(encZ2, stmt.C, proof.Z1, N02)
	right1 := ATimesBToTheCModN(proof.A, stmt.D, e, N02)
	if left1.Cmp(right1) != 0 {
		return false
	}

	// check if g^z1 == Bx *X^e in G
	left2 := crypto.ScalarBaseMult(ec, proof.Z1)
	right2, err := proof.Bx.Add(stmt.X.ScalarMult(e))
	if err != nil || !left2.Equals(right2) {
		return false
	}

    // otherwise third verification equation trivially true
    if IsZero(proof.Wy) || IsZero(proof.By) {
        return false
    }

	// check if (1+N1)^z2 * wy^N1 == By * Y^e mod N1^2
	N12 := new(big.Int).Mul(stmt.N1, stmt.N1)
	pkN1 := &paillier.PublicKey{N: stmt.N1}
	left3 := pkN1.EncryptWithRandomnessNoErrChk(proof.Z2, proof.Wy)
	right3 := ATimesBToTheCModN(proof.By, stmt.Y, e, N12)
	if left3.Cmp(right3) != 0 {
		return false
	}

	// check if s^z1 * t^z3 == E * S^e mod Nhat
	left4 := rp.Commit(proof.Z1, proof.Z3)
	right4 := ATimesBToTheCModN(proof.E, proof.S, e, rp.N)
	if left4.Cmp(right4) != 0 {
		return false
	}

	// check if s^z2 * t^z4 == F*T^e mod Nhat
	left5 := rp.Commit(proof.Z2, proof.Z4)
	right5 := ATimesBToTheCModN(proof.F, proof.T, e, rp.N)
	if left5.Cmp(right5) != 0 {
		return false
	}

	// Check z1 in [-2^{ell+epsilon}...+2^{ell+epsilon}]
	if !NewEll(stmt.Ell).InRange(proof.Z1) {
		return false
	}

	// Check z2 in [-2^{ellprime+epsilon}...+2^{ellprime+epsilon}]
	if !NewEll(stmt.EllPrime).InRange(proof.Z2) {
		return false
	}

	return true
}

func (proof *AffGProof) GetChallenge(stmt *AffGStatement, rp *RingPedersenParams) *big.Int {
	ecParams := stmt.X.Curve().Params()
	msg := []*big.Int{
		ecParams.Gx, ecParams.Gy, ecParams.N,
		stmt.Ell, stmt.EllPrime,
		stmt.N0, stmt.N1,
		stmt.X.X(),
		stmt.X.Y(),
		stmt.Y,
		stmt.C,
		stmt.D,
		rp.N, rp.S, rp.T,
		proof.A, proof.Bx.X(), proof.Bx.Y(), proof.By, proof.E, proof.S, proof.F, proof.T,
	}
	e := common.SHA512_256i(msg...)
	q := Q(stmt.X.Curve())
	return common.RejectionSample(q, e)
}

func (proof *AffGProof) IsNil() bool {
	return proof == nil
}

func (proof *AffGProof) Parts() int {
	return AffGProofParts
}

func (proof *AffGProof) Bytes() [][]byte {
	return [][]byte{
		proof.A.Bytes(),
		proof.Bx.X().Bytes(),
		proof.Bx.Y().Bytes(),
		proof.By.Bytes(),
		proof.E.Bytes(),
		proof.S.Bytes(),
		proof.F.Bytes(),
		proof.T.Bytes(),
		proof.Z1.Bytes(),
		proof.Z2.Bytes(),
		proof.Z3.Bytes(),
		proof.Z4.Bytes(),
		proof.W.Bytes(),
		proof.Wy.Bytes(),
	}
}

func (proof *AffGProof) NotNil() bool {
	if proof.IsNil() {
		return false
	}
	return proof.A != nil &&
		proof.Bx != nil &&
		proof.E != nil &&
		proof.S != nil &&
		proof.F != nil &&
		proof.T != nil &&
		proof.Z1 != nil &&
		proof.Z2 != nil &&
		proof.Z3 != nil &&
		proof.Z4 != nil &&
		proof.W != nil &&
		proof.Wy != nil
}

func (proof *AffGProof) ProofFromBytes(ec elliptic.Curve, bzs [][]byte) (Proof, error) {
	if !common.NonEmptyMultiBytes(bzs, AffGProofParts) {
		return nil, fmt.Errorf("expected %d byte parts to construct AffGProof", AffGProofParts)
	}
	Bx, err := crypto.NewECPoint(
		ec,
		new(big.Int).SetBytes(bzs[1]),
		new(big.Int).SetBytes(bzs[2]))
	if err != nil {
		return nil, err
	}
	return &AffGProof{
		A:  new(big.Int).SetBytes(bzs[0]),
		Bx: Bx,
		By: new(big.Int).SetBytes(bzs[3]),
		E:  new(big.Int).SetBytes(bzs[4]),
		S:  new(big.Int).SetBytes(bzs[5]),
		F:  new(big.Int).SetBytes(bzs[6]),
		T:  new(big.Int).SetBytes(bzs[7]),
		Z1: new(big.Int).SetBytes(bzs[8]),
		Z2: new(big.Int).SetBytes(bzs[9]),
		Z3: new(big.Int).SetBytes(bzs[10]),
		Z4: new(big.Int).SetBytes(bzs[11]),
		W:  new(big.Int).SetBytes(bzs[12]),
		Wy: new(big.Int).SetBytes(bzs[13]),
	}, nil
}
