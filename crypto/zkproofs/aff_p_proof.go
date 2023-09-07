// Copyright 2023 Circle
//
// This file implements proof aff-p from CGG21 Appendix C.3 Figure 26.
// The prover has secret input (x, y, rho, rhox, rhoy) and the
// verifier checks the proof against the statement (N0, N1 C, D, X, Y)
//  C = PaillierEncrypt(N0, c)
//  D  = C^x * (1+N0)^y * rho^N0 mod N0^2
//  X = (1+N1)^x * rhox^N1 mod N1^2
//  Y = (1+N1)^y * rhoy^N1 mod N1^2
//  x \in [-2^ell,2^ell] where ell=|G|
//  y \in [-2^ell',2^ell'] where ell'=|G|
//
// the prover and verifier have auxiliary proof parameters
// Nhat (safe bi-prime) and s,t\in Z/Nhat* (Ring Pedersen parameters)
// The Verifier must generate the values (Nhat, s, t)
// while the prover generates N0, N1.

package zkproofs

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto/paillier"
)

const (
	AffPProofParts = 14
)

// Note: (z1, z2, z3, z4, w, wx, wy) are lowercase in CGG21 Figure 29.
type AffPProof struct {
	A  *big.Int // mod N02
	Bx *big.Int // mod N12
	By *big.Int // mod N12
	E  *big.Int // mod Nhat
	S  *big.Int // mod Nhat
	F  *big.Int // mod Nhat
	T  *big.Int // mod Nhat
	Z1 *big.Int // \in [-2^ell+epsilon,2^ell+epsilon]
	Z2 *big.Int //  \in [-2^ell+epsilon,2^ell+epsilon]
	Z3 *big.Int //  \in [-2^ell+epsilon,2^ell+epsilon]
	Z4 *big.Int //  \in [-2^ell+epsilon,2^ell+epsilon]
	W  *big.Int // mod N0
	Wx *big.Int // mod N1
	Wy *big.Int // mod N1
}

type AffPWitness struct {
	X    *big.Int // \in [-2^ell,2^ell] where ell=|G|
	Y    *big.Int // \in [-2^ell,2^ell] where ell=|G|
	Rho  *big.Int // mod N0
	Rhox *big.Int // mod N1
	Rhoy *big.Int // mod N1
}

type AffPStatement struct {
	C        *big.Int // mod N0^2 - Paillier ciphertext
	D        *big.Int // mod N0^2 - Paillier ciphertext
	X        *big.Int // mod N1^2 - Paillier ciphertext
	Y        *big.Int // mod N1^2 - Paillier ciphertext
	N0       *big.Int // Paillier public key
	N1       *big.Int // Paillier public key
	Ell      *big.Int // max bitsize of x
	EllPrime *big.Int // max bitsize of y
	EC       elliptic.Curve
}

// aff-p from CGG21 Appendix C.3 Figure 26
func NewAffPProof(wit *AffPWitness, stmt *AffPStatement, rp *RingPedersenParams) (*AffPProof, error) {
	N02 := new(big.Int).Mul(stmt.N0, stmt.N0)
	ecpc := NewEll(stmt.Ell)
	ecpcprime := NewEll(stmt.EllPrime)

	// check input in range
	if !ecpc.InRange(wit.X) {
		return nil, errors.New("NewAffPProof: wit.X not in range.")
	}
	if !ecpcprime.InRange(wit.Y) {
		return nil, errors.New("NewAffPProof: wit.Y not in range.")
	}

	// 1. Prover samples alpha, beta, r, rx, ry, gamma, m, delta, mu
	alpha := common.GetRandomPositiveInt(ecpc.TwoPowEllPlusEpsilon)
	beta := common.GetRandomPositiveInt(ecpcprime.TwoPowEllPlusEpsilon)
	r := common.GetRandomPositiveInt(stmt.N0)
	rx := common.GetRandomPositiveInt(stmt.N1)
	ry := common.GetRandomPositiveInt(stmt.N1)
	gammaRange := new(big.Int).Mul(ecpc.TwoPowEllPlusEpsilon, rp.N)
	gamma := common.GetRandomPositiveInt(gammaRange)
	mRange := new(big.Int).Mul(ecpc.TwoPowEll, rp.N)
	m := common.GetRandomPositiveInt(mRange)
	// CGG21 has a typo: says
	//    - sample delta from +-2^{ell+epsilon} * Nhat
	//    - sample mu from +-2^{ell} * Nhat
	// This should be:
	//    - sample delta from +-2^{ell'+epsilon} * Nhat
	//    - sample mu from +-2^{ell'} * Nhat
	deltaRange := new(big.Int).Mul(ecpcprime.TwoPowEllPlusEpsilon, rp.N)
	delta := common.GetRandomPositiveInt(deltaRange)
	muRange := new(big.Int).Mul(ecpcprime.TwoPowEll, rp.N)
	mu := common.GetRandomPositiveInt(muRange)

	// A = C^alpha * (1 + N0)^\beta *r^N0  mod N02
	//   = C^alpha * Encrypt(N0, beta, r) mod N02
	pkN0 := &paillier.PublicKey{N: stmt.N0}
	Aprime, err := pkN0.EncryptWithRandomness(beta, r)
	if err != nil {
		return nil, errors.New("NewAffPProof: could not create A.")
	}
	A := ATimesBToTheCModN(Aprime, stmt.C, alpha, N02)

	// Bx = (1+N1)^alpha * rx^N1 mod N1^2
	pkN1 := &paillier.PublicKey{N: stmt.N1}
	Bx, err := pkN1.EncryptWithRandomness(alpha, rx)
	if err != nil {
		return nil, errors.New("NewAffPProof: could not create Bx.")
	}

	// By = (1+N1)^beta * ry^N1 mod N1^2
	By, err := pkN1.EncryptWithRandomness(beta, ry)
	if err != nil {
		return nil, errors.New("NewAffPProof: could not create By.")
	}

	// E = s^alpha * t^gamma mod Nhat
	E := rp.Commit(alpha, gamma)

	// S = s^x * t^m mod Nhat
	S := rp.Commit(wit.X, m)

	// F = s^beta * t^delta mod Nhat
	F := rp.Commit(beta, delta)

	// T = s^y * t^mu mod Nhat
	T := rp.Commit(wit.Y, mu)

	// 2. hash to get challenge
	proof := &AffPProof{
		A:  A,
		Bx: Bx,
		By: By,
		E:  E,
		S:  S,
		F:  F,
		T:  T,
	}
	e := proof.GetChallenge(stmt, rp)

	// 3. prover sends (z1, z2, z3,z4, w, wx, wy)
	// z1 := alpha + e * x
	proof.Z1 = APlusBC(alpha, e, wit.X)
	// Check z1 in [-2^{ell+epsilon}...+2^{ell+epsilon}]
	if !ecpc.InRange(proof.Z1) {
		return nil, errors.New("NewAffPProof: could not create Z1 in range.")
	}

	// z2 := beta + e * y
	proof.Z2 = APlusBC(beta, e, wit.Y)
	// Check z1 in [-2^{ellprime+epsilon}...+2^{ellprime+epsilon}]
	if !ecpcprime.InRange(proof.Z2) {
		return nil, errors.New("NewAffPProof: could not create Z2 in range.")
	}

	// z3 := gamma + e * m
	proof.Z3 = APlusBC(gamma, e, m)

	// z4 := delta + e * mu
	proof.Z4 = APlusBC(delta, e, mu)

	// w = r * roe^e mod N0
	proof.W = ATimesBToTheCModN(r, wit.Rho, e, stmt.N0)

	// wx = rx * roex^e mod N1
	proof.Wx = ATimesBToTheCModN(rx, wit.Rhox, e, stmt.N1)

	// wy = ry * roey^e mod N1
	proof.Wy = ATimesBToTheCModN(ry, wit.Rhoy, e, stmt.N1)

	return proof, nil
}

// aff-p from CGG21 Appendix C.3 Figure 26
// TODO: determine if there are some values that need to be excluded (e.g. A /= 0).
func (proof *AffPProof) Verify(stmt *AffPStatement, rp *RingPedersenParams) bool {
	N02 := new(big.Int).Mul(stmt.N0, stmt.N0)
	N12 := new(big.Int).Mul(stmt.N1, stmt.N1)

	if proof.IsNil() {
		return false
	}
	if stmt.N0.Sign() != 1 || stmt.N1.Sign() != 1 || rp.N.Sign() != 1 {
		return false
	}

	// Get challenge
	e := proof.GetChallenge(stmt, rp)

	// check C^z1 (1+N0)^z2 w^N0 mod N02 == A * D^e mod N02
	// left1prime := (1+N0)^z1 w^N0 mod N02
	pkN0 := &paillier.PublicKey{N: stmt.N0}
	left1prime, err := pkN0.EncryptWithRandomness(proof.Z2, proof.W)
	left1 := ATimesBToTheCModN(left1prime, stmt.C, proof.Z1, N02)
	right1 := ATimesBToTheCModN(proof.A, stmt.D, e, N02)
	if err != nil || left1.Cmp(right1) != 0 {
		return false
	}

	// check (1+N1)^z1 wx^N1 mod N1^2 == Bx * X^e mod N1^2
	pkN1 := &paillier.PublicKey{N: stmt.N1}
	left2, err := pkN1.EncryptWithRandomness(proof.Z1, proof.Wx)
	right2 := ATimesBToTheCModN(proof.Bx, stmt.X, e, N12)
	if err != nil || left2.Cmp(right2) != 0 {
		return false
	}

	// check (1+N1)^z2 wy^N1 mod N1^2 == By * Y^e mod N1^2
	left3, err := pkN1.EncryptWithRandomness(proof.Z2, proof.Wy)
	right3 := ATimesBToTheCModN(proof.By, stmt.Y, e, N12)
	if err != nil || left3.Cmp(right3) != 0 {
		return false
	}

	// check s^z1 * t^z3 mod Nhat == E * S^e mod Nhat
	left4 := rp.Commit(proof.Z1, proof.Z3)
	right4 := ATimesBToTheCModN(proof.E, proof.S, e, rp.N)
	if err != nil || left4.Cmp(right4) != 0 {
		return false
	}

	// check s^z2 * t^z4 mod Nhat == F * T^e mod Nhat
	left5 := rp.Commit(proof.Z2, proof.Z4)
	right5 := ATimesBToTheCModN(proof.F, proof.T, e, rp.N)
	if err != nil || left5.Cmp(right5) != 0 {
		return false
	}

	// Check z1 in [-2^{ell+epsilon}...+2^{ell+epsilon}]
	if !NewEll(stmt.Ell).InRange(proof.Z1) {
		return false
	}

	// Check z2 in [-2^{ell'+epsilon}...+2^{ell'+epsilon}]
	if !NewEll(stmt.EllPrime).InRange(proof.Z2) {
		return false
	}

	return true
}

func (proof *AffPProof) GetChallenge(stmt *AffPStatement, rp *RingPedersenParams) *big.Int {
	q := stmt.EC.Params().N
	// hash to get challenge
	msg := []*big.Int{
		stmt.Ell, stmt.EllPrime,
		stmt.C, stmt.D, stmt.X, stmt.Y, stmt.N0, stmt.N1,
		rp.N, rp.S, rp.T,
		proof.A, proof.Bx, proof.By, proof.E, proof.S, proof.F, proof.T,
	}
	e := common.SHA512_256i(msg...)
	return common.RejectionSample(q, e)
}

func (proof *AffPProof) IsNil() bool {
	return proof == nil
}

func (proof *AffPProof) Parts() int {
	return AffPProofParts
}

func (proof *AffPProof) Bytes() [][]byte {
	return [][]byte{
		proof.A.Bytes(),
		proof.Bx.Bytes(),
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
		proof.Wx.Bytes(),
		proof.Wy.Bytes(),
	}
}

func (proof *AffPProof) ProofFromBytes(ec elliptic.Curve, bzs [][]byte) (Proof, error) {
	if !common.NonEmptyMultiBytes(bzs, AffPProofParts) {
		return nil, fmt.Errorf("expected %d byte parts to construct AffPProof", AffPProofParts)
	}
	return &AffPProof{
		A:  new(big.Int).SetBytes(bzs[0]),
		Bx: new(big.Int).SetBytes(bzs[1]),
		By: new(big.Int).SetBytes(bzs[2]),
		E:  new(big.Int).SetBytes(bzs[3]),
		S:  new(big.Int).SetBytes(bzs[4]),
		F:  new(big.Int).SetBytes(bzs[5]),
		T:  new(big.Int).SetBytes(bzs[6]),
		Z1: new(big.Int).SetBytes(bzs[7]),
		Z2: new(big.Int).SetBytes(bzs[8]),
		Z3: new(big.Int).SetBytes(bzs[9]),
		Z4: new(big.Int).SetBytes(bzs[10]),
		W:  new(big.Int).SetBytes(bzs[11]),
		Wx: new(big.Int).SetBytes(bzs[12]),
		Wy: new(big.Int).SetBytes(bzs[13]),
	}, nil
}
