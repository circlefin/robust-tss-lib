//  Copyright (c) 2023, Circle Internet Financial, LTD.
//  All rights reserved
//
// This file implements proof mul from CGG21 Appendix C.6 Figure 29.
// The prover has secret input (x, rho, rhox) and
// the verifier checks the proof against the statement (N, X, Y, C)
// X =(1 + N)^x rhox^N mod N^2
// C = Y^x rho^N mod N^2

package zkproofs

import (
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/common"
)

const (
	MulProofParts = 5
)

// Note: (z,u,v) are lowercase in CGG21 Figure 29.
type MulProof struct {
	A *big.Int // mod N2
	B *big.Int // mod N2
	Z *big.Int // mod N
	U *big.Int // mod N2
	V *big.Int // mod N2
}

type MulWitness struct {
	X    *big.Int // lowercase in Figure 29
	Rho  *big.Int
	Rhox *big.Int
}

type MulStatement struct {
	N *big.Int // Paillier public key
	X *big.Int // Paillier ciphertext
	Y *big.Int // Paillier ciphertext
	C *big.Int // Paillier ciphertext
}

// mul in CGG21 in CGG21 Appendix C.6 Figure 29
func NewMulProof(wit *MulWitness, stmt *MulStatement) *MulProof {
	// 1. Prover samples and computes
	alpha := common.GetRandomPositiveInt(stmt.N)
	r := common.GetRandomPositiveInt(stmt.N)
	s := common.GetRandomPositiveInt(stmt.N)

	//A = Y^alpha * r^N mod N^2
	N2 := new(big.Int).Mul(stmt.N, stmt.N)
	A := PseudoPaillierEncrypt(stmt.Y, alpha, r, stmt.N, N2)

	// B = B = (1 + N)^alpha * s^N mod N^2
	NPlusOne := new(big.Int)
	NPlusOne.Add(stmt.N, big.NewInt(1))
	B := PseudoPaillierEncrypt(NPlusOne, alpha, s, stmt.N, N2)

	proof := &MulProof{
		A: A,
		B: B,
	}

	// 2. hash to get challenge
	e := proof.GetChallenge(stmt)

	// 3. prover sends (z, u, v)
	// z := alpha + e * x
	proof.Z = APlusBC(alpha, e, wit.X)

	// u := r * rho^e mod N (typo: Fig 29 omits mod N)
	proof.U = ATimesBToTheCModN(r, wit.Rho, e, stmt.N)

	// v := s * rhox^e mod N
	proof.V = ATimesBToTheCModN(s, wit.Rhox, e, stmt.N)

	return proof
}

// mul in CGG21 in CGG21 Appendix C.6 Figure 29
// The Verifier checks the proof against the statement (N, X, Y, C)
func (proof *MulProof) Verify(stmt *MulStatement) bool {
	if proof == nil {
		return false
	}

	if stmt.N.Sign() != 1 {
		return false
	}

	N2 := new(big.Int).Mul(stmt.N, stmt.N)
	// hash to get challenge
	e := proof.GetChallenge(stmt)

	// otherwise first verification equation trivially true
	if IsZero(proof.U) || IsZero(proof.A) {
		return false
	}

	// check Y^z * u^N mod N2 == A * C^e mod N2
	left1 := PseudoPaillierEncrypt(stmt.Y, proof.Z, proof.U, stmt.N, N2)
	right1 := ATimesBToTheCModN(proof.A, stmt.C, e, N2)
	if left1.Cmp(right1) != 0 {
		return false
	}

	// otherwise first verification equation trivially true
	if IsZero(proof.V) || IsZero(proof.B) {
		return false
	}

	// Second verification in Figure 29 states to check
	// (1 + N)^z * v^N == B * X^e mod N2
	// Note: CGG21 Fig 29 typo has c^N instead of v^N
	Nplus1 := new(big.Int).Add(big.NewInt(1), stmt.N)
	left2 := PseudoPaillierEncrypt(Nplus1, proof.Z, proof.V, stmt.N, N2)
	right2 := ATimesBToTheCModN(proof.B, stmt.X, e, N2)

	if left2.Cmp(right2) != 0 {
		return false
	}

	return true
}

func (proof *MulProof) GetChallenge(stmt *MulStatement) *big.Int {
	msg := []*big.Int{stmt.N, stmt.X, stmt.Y, stmt.C, proof.A, proof.B}
	e := common.SHA512_256i(msg...)
	return e
}

func (proof *MulProof) Nil() bool {
	if proof == nil {
		return true
	}
	if proof.A == nil || proof.B == nil || proof.Z == nil || proof.U == nil || proof.V == nil {
		return true
	}
	return false
}

func (proof *MulProof) Bytes() [MulProofParts][]byte {
	return [...][]byte{
		proof.A.Bytes(),
		proof.B.Bytes(),
		proof.Z.Bytes(),
		proof.U.Bytes(),
		proof.V.Bytes(),
	}
}

func MulProofFromBytes(bzs [][]byte) (*MulProof, error) {
	if !common.NonEmptyMultiBytes(bzs, MulProofParts) {
		return nil, fmt.Errorf("expected %d byte parts to construct MulProof", MulProofParts)
	}
	return &MulProof{
		A: new(big.Int).SetBytes(bzs[0]),
		B: new(big.Int).SetBytes(bzs[1]),
		Z: new(big.Int).SetBytes(bzs[2]),
		U: new(big.Int).SetBytes(bzs[3]),
		V: new(big.Int).SetBytes(bzs[4]),
	}, nil
}
