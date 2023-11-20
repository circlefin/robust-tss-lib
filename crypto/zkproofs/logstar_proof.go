// Copyright (c) 2023, Circle Internet Financial, LTD. All rights reserved.
//
//  SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// This file implements proof log* from CGG21 Appendix C.2 Figure 25.
// The Prover has secret input (x, rho) and
// the verifier checks the proof against the statement (N0, C, X)
// C =(1 + N0)^x rhox^N0 mod N0^2
// X = g^x \in G
// the prover and verifier have auxiliary proof parameters
// Nhat (safe bi-prime) and s,t\in Z/Nhat* (Ring Pedersen parameters)
// The Verifier must generate the values (Nhat, s, t)
// while the prover generates N0.

package zkproofs

import (
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/bnb-chain/tss-lib/v2/crypto/paillier"
)

const (
	LogStarProofParts = 8
)

// Note: (z,u,v) are lowercase in CGG21 Figure 29.
type LogStarProof struct {
	S  *big.Int        // mod Nhat
	A  *big.Int        // mod N02
	Y  *crypto.ECPoint // G
	D  *big.Int        // mod Nhat
	Z1 *big.Int        //
	Z2 *big.Int        // mod N0
	Z3 *big.Int        //
}

type LogStarWitness struct {
	X   *big.Int
	Rho *big.Int
}

type LogStarStatement struct {
	Ell *big.Int
	N0  *big.Int
	C   *big.Int
	X   *crypto.ECPoint
	G   *crypto.ECPoint
}

// log* in CGG21 in CGG21 Appendix C.2 Figure 25
func NewLogStarProof(wit *LogStarWitness, stmt *LogStarStatement, rp *RingPedersenParams) *LogStarProof {
	if stmt.G == nil {
		ec := stmt.X.Curve()
		stmt.G = crypto.NewECPointNoCurveCheck(ec, ec.Params().Gx, ec.Params().Gy)
	}

	// derive some parameters
	ecpc := NewEll(stmt.Ell)

	// 1. Prover samples alpha, mu, r, gamma
	alpha := common.GetRandomPositiveInt(ecpc.TwoPowEllPlusEpsilon)
	muRange := new(big.Int).Mul(ecpc.TwoPowEll, rp.N)
	mu := common.GetRandomPositiveInt(muRange)
	// CGG21 has typo - says sample from Z*_N (where N is undefined)
	// It should be Z*_N0  because it is used to compute A is a Paillier cypertext.
	r := common.GetRandomPositiveInt(stmt.N0)
	gammRange := new(big.Int).Mul(ecpc.TwoPowEllPlusEpsilon, rp.N)
	gamma := common.GetRandomPositiveInt(gammRange)

	// S=s^x *t^mu mod Nhat
	S := rp.Commit(wit.X, mu)

	//A = (1+N0)^alpha * r^N0 mod N02
	// we can ignore error when encrypting because we chose the range
	pkN0 := &paillier.PublicKey{N: stmt.N0}
	A, _ := pkN0.EncryptWithRandomness(alpha, r)

	// Y=g^alpha
	Y := stmt.G.ScalarMult(alpha)

	// D=s^alpha *t^gamma mod Nhat
	D := rp.Commit(alpha, gamma)

	proof := &LogStarProof{
		S: S,
		A: A,
		Y: Y,
		D: D,
	}
	// 2. hash to get challenge
	e := proof.GetChallenge(stmt, rp)

	// 3. prover sends (z1, z2, z3)
	// z1 := alpha + e * x
	proof.Z1 = APlusBC(alpha, e, wit.X)

	// z2 = r *rho^e mod N0
	proof.Z2 = ATimesBToTheCModN(r, wit.Rho, e, stmt.N0)

	// z3 = gammma + e * mu
	proof.Z3 = APlusBC(gamma, e, mu)

	return proof
}

// log* from CGG21 Appendix C.2 Figure 25.
// The Verifier checks the proof against the statement (N0, C, X)
func (proof *LogStarProof) Verify(stmt *LogStarStatement, rp *RingPedersenParams) bool {
	if proof == nil {
		return false
	}

	if stmt.N0.Sign() != 1 {
		return false
	}

	if stmt.G == nil {
		ec := stmt.X.Curve()
		stmt.G = crypto.NewECPointNoCurveCheck(ec, ec.Params().Gx, ec.Params().Gy)
	}

	// hash to get challenge
	e := proof.GetChallenge(stmt, rp)

	// otherwise first verification equation is trivially true
	if IsZero(proof.A) || IsZero(proof.Z2) {
		return false
	}

	// check (1+N0)^z1 * z2^N0 mod N02 == A * C^e mod N02
	N02 := new(big.Int).Mul(stmt.N0, stmt.N0)
	pkN0 := &paillier.PublicKey{N: stmt.N0}
	left1, err := pkN0.EncryptWithRandomness(proof.Z1, proof.Z2)
	right1 := ATimesBToTheCModN(proof.A, stmt.C, e, N02)
	if err != nil || left1.Cmp(right1) != 0 {
		return false
	}

	// check g^z1 = Y * X^e \in G
	left2 := stmt.G.ScalarMult(proof.Z1)
	right2, err := proof.Y.Add(stmt.X.ScalarMult(e))
	if err != nil || !left2.Equals(right2) {
		return false
	}

	// check s^z1 * t^z3 == D * S^e mod Nhat
	left3 := rp.Commit(proof.Z1, proof.Z3)
	right3 := ATimesBToTheCModN(proof.D, proof.S, e, rp.N)
	if left3.Cmp(right3) != 0 {
		return false
	}

	// Check z1 in [-2^{ell+epsilon}...+2^{ell+epsilon}]
	if !NewEll(stmt.Ell).InRange(proof.Z1) {
		return false
	}

	return true
}

func (proof *LogStarProof) GetChallenge(stmt *LogStarStatement, rp *RingPedersenParams) *big.Int {
	params := stmt.X.Curve().Params()
	msg := []*big.Int{
		stmt.Ell, params.Gx, params.Gy, params.N, big.NewInt(int64(params.BitSize)),
		stmt.N0, stmt.X.X(), stmt.X.Y(), stmt.C, stmt.G.X(), stmt.G.Y(),
		rp.N, rp.S, rp.T,
		proof.S, proof.A, proof.Y.X(), proof.Y.Y(), proof.D}
	e := common.SHA512_256i(msg...)
	return e
}

func (proof *LogStarProof) Parts() int {
	return LogStarProofParts
}

func (proof *LogStarProof) IsNil() bool {
	if proof == nil {
		return true
	}
	if proof.S == nil || proof.A == nil || proof.Y == nil || proof.D == nil || proof.Z1 == nil || proof.Z2 == nil || proof.Z3 == nil {
		return true
	}
	return false
}

func (proof *LogStarProof) Bytes() [][]byte {
	return [][]byte{
		proof.S.Bytes(),
		proof.A.Bytes(),
		proof.Y.X().Bytes(),
		proof.Y.Y().Bytes(),
		proof.D.Bytes(),
		proof.Z1.Bytes(),
		proof.Z2.Bytes(),
		proof.Z3.Bytes(),
	}
}

func (proof *LogStarProof) ProofFromBytes(ec elliptic.Curve, bzs [][]byte) (Proof, error) {
	if !common.NonEmptyMultiBytes(bzs, LogStarProofParts) {
		return nil, fmt.Errorf("expected %d byte parts to construct LogStarProof", LogStarProofParts)
	}
	Y, err := crypto.NewECPoint(
		ec,
		new(big.Int).SetBytes(bzs[2]),
		new(big.Int).SetBytes(bzs[3]))
	if err != nil {
		return nil, err
	}
	return &LogStarProof{
		S:  new(big.Int).SetBytes(bzs[0]),
		A:  new(big.Int).SetBytes(bzs[1]),
		Y:  Y,
		D:  new(big.Int).SetBytes(bzs[4]),
		Z1: new(big.Int).SetBytes(bzs[5]),
		Z2: new(big.Int).SetBytes(bzs[6]),
		Z3: new(big.Int).SetBytes(bzs[7]),
	}, nil
}
