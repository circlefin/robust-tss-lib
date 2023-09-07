// Copyright 2023 Circle
//
// This file implements proof mul* from CGG21 Appendix C.6 Figure 31.
// The prover has secret (x, rho) and
// the verifier checks the proof against the statement (N0, C, D, X)
// X = g^x
// D = C^x * rho^No mod N0^2
// the prover and verifier have auxiliary proof parameters
// Nhat (safe bi-prime) and s,t\in Z/Nhat* (Ring Pedersen parameters)
// The Verifier must generate the values (Nhat, s, t)
// while the prover generates N0.

package zkproofs

import (
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
)

const (
	MulStarProofParts = 8
)

// Note: (z1,z2,w) are lowercase in CGG21 Figure 29.
type MulStarProof struct {
	A  *big.Int        // mod N02
	Bx *crypto.ECPoint // mod q (EC point)
	S  *big.Int        // mod Nhat
	E  *big.Int        // mod Nhat (Fig 31 omits modular reduction)
	Z1 *big.Int        // ?
	Z2 *big.Int        // ?
	W  *big.Int        // mod N0
}

type MulStarWitness struct {
	X   *big.Int
	Rho *big.Int
}

type MulStarStatement struct {
	Ell *big.Int
	N0  *big.Int
	C   *big.Int
	D   *big.Int
	X   *crypto.ECPoint
}

// mul* in CGG21 Appendix C.6 Figure 31
// todo: check proof for typos - especially modular reduction for some values.
func NewMulStarProof(wit *MulStarWitness, stmt *MulStarStatement, rp *RingPedersenParams) *MulStarProof {
	// derive some parameters
	ec := stmt.X.Curve()
	ecpc := NewEll(stmt.Ell)
	N02 := new(big.Int).Mul(stmt.N0, stmt.N0)

	// 1. Prover samples alpha, r, gamma, m
	// note: CGG21 has typo with extra variable ry that is not used
	alpha := common.GetRandomPositiveInt(ecpc.TwoPowEllPlusEpsilon)
	r := common.GetRandomPositiveInt(stmt.N0)
	gammRange := new(big.Int).Mul(ecpc.TwoPowEllPlusEpsilon, rp.N)
	gamma := common.GetRandomPositiveInt(gammRange)
	mRange := new(big.Int).Mul(ecpc.TwoPowEll, rp.N)
	m := common.GetRandomPositiveInt(mRange)

	// 1. Prover computes
	// A = C^alpha r^N0 mod N02
	// Note: CGG21 has a typo A = C^alpha (1+N0)^beta r^N0 mod N02
	// The extra factor (1+N0)^beta would cause the first verification equation to fail
	A := PseudoPaillierEncrypt(stmt.C, alpha, r, stmt.N0, N02)
	// Bx = g^alpha \in G
	Bx := crypto.ScalarBaseMult(ec, alpha)
	// E = s^alpha * t^gamma mod Nhat (CGG21 omits mod Nhat)
	E := rp.Commit(alpha, gamma)
	// S = s^x * t^m md Nhat
	S := rp.Commit(wit.X, m)
	proof := &MulStarProof{
		A:  A,
		Bx: Bx,
		E:  E,
		S:  S,
	}

	// 2. hash to get challenge
	e := proof.GetChallenge(stmt, rp)

	// 3. Prover computes
	// z1 = alpha + ex
	proof.Z1 = APlusBC(alpha, e, wit.X)
	// z2 = gamma + em
	proof.Z2 = APlusBC(gamma, e, m)
	// w = r * rho^e mod N0
	proof.W = ATimesBToTheCModN(r, wit.Rho, e, stmt.N0)

	return proof
}

// mul in CGG21 in CGG21 Appendix C.6 Figure 29
// The Verifier checks the proof against the statement (N, X, Y, C)
// TODO: determine if there are some values that need to be excluded (e.g. A /= 0).
func (proof *MulStarProof) Verify(stmt *MulStarStatement, rp *RingPedersenParams) bool {
	if proof == nil {
		return false
	}

	if stmt.N0.Sign() != 1 {
		return false
	}

	// derive some parameters
	ec := stmt.X.Curve()
	N02 := new(big.Int).Mul(stmt.N0, stmt.N0)

	// hash to get challenge
	e := proof.GetChallenge(stmt, rp)

	// Check C^z1 w^N0 mod N02 == A * D^e mod N02
	left1 := PseudoPaillierEncrypt(stmt.C, proof.Z1, proof.W, stmt.N0, N02)
	right1 := ATimesBToTheCModN(proof.A, stmt.D, e, N02)
	if left1.Cmp(right1) != 0 {
		return false
	}

	// Check g^z1 == Bx * X^e \in G
	left2 := crypto.ScalarBaseMult(ec, proof.Z1)
	right2, err := proof.Bx.Add(stmt.X.ScalarMult(e))
	if err != nil || !left2.Equals(right2) {
		return false
	}

	// Check s^z1 * t^z2 == E * S^e mod Nhat
	left3 := rp.Commit(proof.Z1, proof.Z2)
	right3 := ATimesBToTheCModN(proof.E, proof.S, e, rp.N)
	if left3.Cmp(right3) != 0 {
		return false
	}

	// Check z1 in +-2^{ell+epsilon}
	if !NewEll(stmt.Ell).InRange(proof.Z1) {
		return false
	}
	return true
}

func (proof *MulStarProof) GetChallenge(stmt *MulStarStatement, rp *RingPedersenParams) *big.Int {
	params := stmt.X.Curve().Params()
	msg := []*big.Int{
		stmt.Ell, params.Gx, params.Gy, params.N, big.NewInt(int64(params.BitSize)),
		stmt.N0, stmt.C, stmt.D, stmt.X.X(), stmt.X.Y(),
		rp.N, rp.S, rp.T,
		proof.A, proof.Bx.X(), proof.Bx.Y(), proof.S, proof.E,
	}
	e := common.SHA512_256i(msg...)
	return e
}

func (proof *MulStarProof) Nil() bool {
	if proof == nil {
		return true
	}
	if proof.A == nil || proof.Bx == nil || proof.E == nil || proof.S == nil || proof.Z1 == nil || proof.Z2 == nil || proof.W == nil {
		return true
	}
	return false
}

func (proof *MulStarProof) IsNil() bool {
	return proof == nil
}

func (proof *MulStarProof) Parts() int {
	return MulStarProofParts
}

func (proof *MulStarProof) Bytes() [][]byte {
	return [][]byte{
		proof.A.Bytes(),
		proof.Bx.X().Bytes(),
		proof.Bx.Y().Bytes(),
		proof.S.Bytes(),
		proof.E.Bytes(),
		proof.Z1.Bytes(),
		proof.Z2.Bytes(),
		proof.W.Bytes(),
	}
}

func (proof *MulStarProof) ProofFromBytes(ec elliptic.Curve, bzs [][]byte) (Proof, error) {
	if !common.NonEmptyMultiBytes(bzs, MulStarProofParts) {
		return nil, fmt.Errorf("expected %d byte parts to construct MulStarProof", MulStarProofParts)
	}
	Bx, err := crypto.NewECPoint(
		ec,
		new(big.Int).SetBytes(bzs[1]),
		new(big.Int).SetBytes(bzs[2]))
	if err != nil {
		return nil, err
	}
	return &MulStarProof{
		A:  new(big.Int).SetBytes(bzs[0]),
		Bx: Bx,
		S:  new(big.Int).SetBytes(bzs[3]),
		E:  new(big.Int).SetBytes(bzs[4]),
		Z1: new(big.Int).SetBytes(bzs[5]),
		Z2: new(big.Int).SetBytes(bzs[6]),
		W:  new(big.Int).SetBytes(bzs[7]),
	}, nil
}
