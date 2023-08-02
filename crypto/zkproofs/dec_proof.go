// Copyright 2023 Circle
//
// This file implements proof dec in CGG21 Appendix C6 Figure 30.
// This is a proof that
//  N0 = Paillier public key
//  C = PaillierEncrypt(N0, y)
//  x = y mod q
// Specifically, the Prover has secret input (y, rho) such that
//  C =(1 + N0)^y rho^N0 mod N0^2
//  x = y mod q
// The verifier checks the proof against the statement (x, N0, C)

package zkproofs

import (
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto/paillier"
)

const (
	DecProofParts = 7
)

// Note: (z1, z2, w) are lowercase in dec in CGG21 Appendix C6 Figure 30.
// There is a typo in Fig 30 that omits S, T from the proof.
type DecProof struct {
	S     *big.Int // mod Nhat
	T     *big.Int // mod Nhat
	A     *big.Int // mod N02
	Gamma *big.Int // mod q (size of |G|)
	Z1    *big.Int // in +- 2^{ell + epsilon}
	Z2    *big.Int // in +- 2^{ell + epsilon} + |Nhat|
	W     *big.Int // mod N0
}

type DecStatement struct {
	Q   *big.Int
	Ell *big.Int
	N0  *big.Int
	C   *big.Int
	X   *big.Int
}

type DecWitness struct {
	Y   *big.Int
	Rho *big.Int
}

// dec in CGG21 Appendix C6 Figure 30.
func NewDecProof(wit *DecWitness, stmt *DecStatement, rp *RingPedersenParams) *DecProof {
	// derive some parameters
	ecpc := NewEll(stmt.Ell)

	// 1. Prover samples alpha, mu, r, gamma
	alpha := common.GetRandomPositiveInt(ecpc.TwoPowEllPlusEpsilon)
	muRange := new(big.Int).Mul(ecpc.TwoPowEll, rp.N)
	mu := common.GetRandomPositiveInt(muRange)
	nuRange := new(big.Int).Mul(ecpc.TwoPowEllPlusEpsilon, rp.N)
	nu := common.GetRandomPositiveInt(nuRange)
	// CGG21 has typo - says sample from Z*_N (where N is undefined)
	// It should be Z*_N0  because it is used to compute A as a Paillier cyphertext.
	r := common.GetRandomPositiveInt(stmt.N0)

	// S=s^y *t^mu mod Nhat
	S := rp.Commit(wit.Y, mu)

	// T = s^alpha * t^nu mod Nhat
	T := rp.Commit(alpha, nu)

	//A = (1+N0)^alpha * r^N0 mod N02
	// we can ignore error when encrypting because we chose the range
	pkN0 := &paillier.PublicKey{N: stmt.N0}
	A, _ := pkN0.EncryptWithRandomness(alpha, r)

	// gamma = alpha mod q
	gamma := new(big.Int).Mod(alpha, stmt.Q)

	proof := &DecProof{
		S:     S,
		T:     T,
		A:     A,
		Gamma: gamma,
	}

	// 2. hash to get challenge
	e := proof.GetChallenge(stmt, rp)

	// 3. prover sends (z1, z2, w)
	// z1 := alpha + e * y
	proof.Z1 = APlusBC(alpha, e, wit.Y)

	// z2 := nu + e * mu
	proof.Z2 = APlusBC(nu, e, mu)

	// w := r * rho^e mod N0
	proof.W = ATimesBToTheCModN(r, wit.Rho, e, stmt.N0)

	return proof
}

// dec in CGG21 Appendix C6 Figure 30.
// The Verifier checks the proof against the statement (N0, C, x)
// TODO: determine if there are some values that need to be excluded (e.g. A /= 0).
func (proof *DecProof) Verify(stmt *DecStatement, rp *RingPedersenParams) bool {
	if proof == nil {
		return false
	}

	if stmt.N0.Sign() != 1 {
		return false
	}

	// hash to get challenge
	e := proof.GetChallenge(stmt, rp)

	// check (1+N0)^z1 * w^N0 mod N02 == A * C^e mod N02
	N02 := new(big.Int).Mul(stmt.N0, stmt.N0)
	N0plus1 := new(big.Int).Add(stmt.N0, big.NewInt(1))
    left1 := PseudoPaillierEncrypt(N0plus1, proof.Z1, proof.W, stmt.N0, N02)
	right1 := ATimesBToTheCModN(proof.A, stmt.C, e, N02)
	if left1.Cmp(right1) != 0 {
		return false
	}

	// check z1 = gamma + e*x mod q
	left2 := new(big.Int).Mod(proof.Z1, stmt.Q)
	right2Int := APlusBC(proof.Gamma, e, stmt.X)
	right2 := new(big.Int).Mod(right2Int, stmt.Q)
	if left2.Cmp(right2) != 0 {
		return false
	}

	// check s^z1 * t^z2 == T * S^e mod Nhat
	left3 := rp.Commit(proof.Z1, proof.Z2)
	right3 := ATimesBToTheCModN(proof.T, proof.S, e, rp.N)
	if left3.Cmp(right3) != 0 {
		return false
	}

	return true
}

func (proof *DecProof) GetChallenge(stmt *DecStatement, rp *RingPedersenParams) *big.Int {
	msg := []*big.Int{
	stmt.Ell, stmt.Q, stmt.N0,
//	stmt.C,
	stmt.X,
//	rp.N, rp.S, rp.T,
//	proof.S, proof.T, proof.A, proof.Gamma,
	}
	e := common.SHA512_256i(msg...)
	return e
}

func (proof *DecProof) Nil() bool {
	if proof == nil {
		return true
	}
	if proof.S == nil || proof.T == nil || proof.A == nil || proof.Gamma == nil || proof.Z1 == nil || proof.Z2 == nil || proof.W == nil {
		return true
	}
	return false
}

func (proof *DecProof) IsNil() bool {
	return proof == nil
}

func (proof *DecProof) Parts() int {
	return DecProofParts
}

func (proof *DecProof) Bytes() [][]byte {
	return [][]byte{
		proof.S.Bytes(),
		proof.T.Bytes(),
		proof.A.Bytes(),
		proof.Gamma.Bytes(),
		proof.Z1.Bytes(),
		proof.Z2.Bytes(),
		proof.W.Bytes(),
	}
}

func (proof *DecProof) ProofFromBytes(ec elliptic.Curve, bzs [][]byte) (Proof, error) {
	if !common.NonEmptyMultiBytes(bzs, DecProofParts) {
		return nil, fmt.Errorf("expected %d byte parts to construct DecProof", DecProofParts)
	}
	return &DecProof{
		S:     new(big.Int).SetBytes(bzs[0]),
		T:     new(big.Int).SetBytes(bzs[1]),
		A:     new(big.Int).SetBytes(bzs[2]),
		Gamma: new(big.Int).SetBytes(bzs[3]),
		Z1:    new(big.Int).SetBytes(bzs[4]),
		Z2:    new(big.Int).SetBytes(bzs[5]),
		W:     new(big.Int).SetBytes(bzs[6]),
	}, nil
}
