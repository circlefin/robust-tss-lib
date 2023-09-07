// Copyright 2023 Circle
//
// This file implements proof enc from CGG21 Section 6.1 Figure 14.
// The prover has secret input (k, rho) and the
// The verifier checks the proof against the statement (N, X, Y, C)
// K =(1 + N0)^k rho^N0 mod N0^2
//  k \in [-2^ell...2^ell]

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
	EncProofParts = 6
)

// Note: (z1, z2, z3) are lowercase in CGG21 Figure 29.
type EncProof struct {
	S  *big.Int // mod Nhat
	A  *big.Int // mod N02
	C  *big.Int // mod Nhat
	Z1 *big.Int // in +- 2^{ell + epsilon}
	Z2 *big.Int // mod N0
	Z3 *big.Int // in +- 2^{ell + epsilon} + |Nhat|
}

type EncStatement struct {
	EC elliptic.Curve
	N0 *big.Int
	K  *big.Int
}

type EncWitness struct {
	K   *big.Int // lowercase k in Figure 14
	Rho *big.Int
}

// enc in CGG21 in CGG21 Section 6.1 Figure 14
func NewEncProof(wit *EncWitness, stmt *EncStatement, rp *RingPedersenParams) (*EncProof, error) {
	// derive some parameters
	ecpc := NewEll(GetEll(stmt.EC))
	if !ecpc.InRangeEll(wit.K) {
		return nil, errors.New("NewEncProof: wit.K must be less than 2^ell.")
	}

	// 1. Prover samples alpha, mu, r, gamma
	alpha := common.GetRandomPositiveInt(ecpc.TwoPowEllPlusEpsilon)
	muRange := new(big.Int).Mul(ecpc.TwoPowEll, rp.N)
	mu := common.GetRandomPositiveInt(muRange)
	// CGG21 has typo - says sample from Z*_N (where N is undefined)
	// It should be Z*_N0  because it is used to compute A as a Paillier cypertext.
	r := common.GetRandomPositiveInt(stmt.N0)
	gammRange := new(big.Int).Mul(ecpc.TwoPowEllPlusEpsilon, rp.N)
	gamma := common.GetRandomPositiveInt(gammRange)

	// S=s^k *t^mu mod Nhat
	S := rp.Commit(wit.K, mu)

	//A = (1+N0)^alpha * r^N0 mod N02
	// we can ignore error when encrypting because we chose the range
	pkN0 := &paillier.PublicKey{N: stmt.N0}
	A, err := pkN0.EncryptWithRandomness(alpha, r)
	if err != nil {
		return nil, err
	}

	// C=s^alpha *t^gamma mod Nhat
	C := rp.Commit(alpha, gamma)

	proof := &EncProof{
		S: S,
		A: A,
		C: C,
	}

	// 2. hash to get challenge
	e := proof.GetChallenge(stmt, rp)

	// 3. prover sends (z1, z2, z3)
	// z1 := alpha + e * k
	proof.Z1 = APlusBC(alpha, e, wit.K)
	// Check z1 in [-2^{ell+epsilon}...+2^{ell+epsilon}]
	if !ecpc.InRange(proof.Z1) {
		return nil, errors.New("NewEncProof: Could not create Z1 in range.")
	}

	// z2 := r * rho^e mod N0
	proof.Z2 = ATimesBToTheCModN(r, wit.Rho, e, stmt.N0)

	// z3 := gamma + e * mu
	proof.Z3 = APlusBC(gamma, e, mu)

	return proof, nil
}

// enc in CGG21 in CGG21 Section 6.1 Figure 14
// The Verifier checks the proof against the statement (N0, K)
// TODO: determine if there are some values that need to be excluded (e.g. A /= 0).
func (proof *EncProof) Verify(stmt *EncStatement, rp *RingPedersenParams) bool {
	if proof == nil {
		return false
	}

	if stmt.N0.Sign() != 1 {
		return false
	}

	// hash to get challenge
	e := proof.GetChallenge(stmt, rp)

    // otherwise first verification equation trivially true
    if IsZero(proof.Z2) || IsZero(proof.A) {
        return false
    }

	// check (1+N0)^z1 * z2^N0 mod N02 == A * K^e mod N02
	N02 := new(big.Int).Mul(stmt.N0, stmt.N0)
	pkN0 := &paillier.PublicKey{N: stmt.N0}
	left1, err := pkN0.EncryptWithRandomness(proof.Z1, proof.Z2)
	right1 := ATimesBToTheCModN(proof.A, stmt.K, e, N02)
	if err != nil || left1.Cmp(right1) != 0 {
		return false
	}

	// check s^z1 * t^z3 == C * S^e mod Nhat
	left2 := rp.Commit(proof.Z1, proof.Z3)
	right2 := ATimesBToTheCModN(proof.C, proof.S, e, rp.N)
	if left2.Cmp(right2) != 0 {
		return false
	}

	// Check z1 in [-2^{ell+epsilon}...+2^{ell+epsilon}]
	if !NewEll(GetEll(stmt.EC)).InRange(proof.Z1) {
		return false
	}

	return true
}

func (proof *EncProof) GetChallenge(stmt *EncStatement, rp *RingPedersenParams) *big.Int {
	q := stmt.EC.Params().N
	msg := []*big.Int{q, stmt.N0, stmt.K, rp.N, rp.S, rp.T, proof.S, proof.A, proof.C}
	e := common.SHA512_256i(msg...)
	return common.RejectionSample(q, e)
}

func (proof *EncProof) Nil() bool {
	if proof == nil {
		return true
	}
	if proof.S == nil || proof.A == nil || proof.C == nil || proof.Z1 == nil || proof.Z2 == nil || proof.Z3 == nil {
		return true
	}
	return false
}

func (proof *EncProof) IsNil() bool {
	return proof == nil
}

func (proof *EncProof) Parts() int {
	return EncProofParts
}

func (proof *EncProof) Bytes() [][]byte {
	return [][]byte{
		proof.S.Bytes(),
		proof.A.Bytes(),
		proof.C.Bytes(),
		proof.Z1.Bytes(),
		proof.Z2.Bytes(),
		proof.Z3.Bytes(),
	}
}

func (proof *EncProof) ProofFromBytes(ec elliptic.Curve, bzs [][]byte) (Proof, error) {
	if !common.NonEmptyMultiBytes(bzs, EncProofParts) {
		return nil, fmt.Errorf("expected %d byte parts to construct EncProof", EncProofParts)
	}
	return &EncProof{
		S:  new(big.Int).SetBytes(bzs[0]),
		A:  new(big.Int).SetBytes(bzs[1]),
		C:  new(big.Int).SetBytes(bzs[2]),
		Z1: new(big.Int).SetBytes(bzs[3]),
		Z2: new(big.Int).SetBytes(bzs[4]),
		Z3: new(big.Int).SetBytes(bzs[5]),
	}, nil
}
