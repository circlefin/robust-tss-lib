//  Copyright (c) 2023, Circle Internet Financial, LTD.
//  All rights reserved
//
// This file modifies the proof aff-g from CGG21 Section 6.2 Figure 15.
// the prover has secret input (x, y, rho, rhoy) while the
// verifier checks the proof against the statement (N0, N1, C, D, Y, X)
//  X = g^x \in G
//  Y = (1+N1)^(q-y) * rhoy^N1 mod N1^2
//  Y^-1 = (1+N1)^(N1-q+y) * rhoy^N1 mod N1^2
//  D = C^x * (1+N0)^(q-y) * rho^N0 mod N0^2
//
// The prover and verifier have auxiliary proof parameters
// Nhat (safe bi-prime) and s,t\in Z/Nhat* (Ring Pedersen parameters)
// The Verifier must generate the values (Nhat, s, t)
// while the prover generates N0, N1.
//
// The chief modification: the prover switches  z2=beta + e*y to z2=beta + e(q-y)

package zkproofs

import (
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/crypto/paillier"
)

// Note: (z,u,v) are lowercase in aff-g from CGG21 Section 6.2 Figure 15.
type AffGInvProof struct {
	AffGProof
}

type AffGInvWitness struct {
	AffGWitness
}

type AffGInvStatement struct {
	AffGStatement
}

// Input Y = (N+1)^y * rho^N mod N2
// Output Y = Y^(-1) * (N+1)^(q-N) mod N^2
func MakeY(Y, q, N *big.Int) (*big.Int, error) {
	pk := &paillier.PublicKey{N: N}
	Yp, err := pk.HomoMultInv(Y)
	if err != nil {
		return nil, err
	}

	qMinusN := new(big.Int).Sub(q, N)
	qMinusNCipher := pk.EncryptWithRandomnessNoErrChk(qMinusN, big.NewInt(1))
	NSquare := new(big.Int).Mul(N, N)
	Yp = common.ModInt(NSquare).Mul(Yp, qMinusNCipher)
	return Yp, err
}

// ec : elliptic.Curve
// sk1: decryption key to Y
// pk0: other public key
// x, y \in Zq
// C : ciphertext under pk
func NewAffGInvWitness(
	ec elliptic.Curve,
	sk1 *paillier.PrivateKey,
	pk0 *paillier.PublicKey,
	x, y, C *big.Int,
) (*AffGInvWitness, *AffGInvStatement, error) {
	q := ec.Params().N

	Y, _, err := sk1.PublicKey.EncryptAndReturnRandomness(y)
	if err != nil {
		return nil, nil, err
	}
	Yp, err := MakeY(Y, q, sk1.PublicKey.N)
	if err != nil {
		return nil, nil, err
	}
	_, rhoy, err := sk1.DecryptFull(Yp)
	if err != nil {
		return nil, nil, err
	}

	//  D = C^x * (1+N0)^(q-y) * rho^N0 mod N0^2
	qMinusY := new(big.Int).Sub(q, y)
	Dprime, rho, err := pk0.EncryptAndReturnRandomness(qMinusY)
	if err != nil {
		return nil, nil, err
	}
	D := ATimesBToTheCModN(Dprime, C, x, pk0.NSquare())

	statement := &AffGInvStatement{
		AffGStatement{
			C:        C,
			D:        D,
			X:        crypto.ScalarBaseMult(ec, x),
			Y:        Y,
			N0:       pk0.N,
			N1:       sk1.PublicKey.N,
			Ell:      GetEll(ec),
			EllPrime: GetEll(ec),
		},
	}
	witness := &AffGInvWitness{
		AffGWitness{
			X:    x,
			Y:    y,
			Rho:  rho,
			Rhoy: rhoy,
		},
	}
	return witness, statement, nil
}

func (stmt *AffGInvStatement) ToAffGStatement() (*AffGStatement, error) {
	q := stmt.X.Curve().Params().N
	Yp, err := MakeY(stmt.Y, q, stmt.N1)
	if err != nil {
		return nil, err
	}

	gstmt := &AffGStatement{
		C:        stmt.C,
		D:        stmt.D,
		X:        stmt.X,
		Y:        Yp,
		N0:       stmt.N0,
		N1:       stmt.N1,
		Ell:      stmt.Ell,
		EllPrime: stmt.EllPrime,
	}
	return gstmt, nil
}

func (wit *AffGInvWitness) ToAffGWitness(stmt *AffGInvStatement) *AffGWitness {
	q := stmt.X.Curve().Params().N
	qMinusY := new(big.Int).Sub(q, wit.Y)
	return &AffGWitness{
		X:    wit.X,
		Y:    qMinusY,
		Rho:  wit.Rho,
		Rhoy: wit.Rhoy,
	}
}

// aff-g from CGG21 Section 6.2 Figure 15.
func NewAffGInvProof(wit *AffGInvWitness, stmt *AffGInvStatement, rp *RingPedersenParams) (*AffGInvProof, error) {
	gwit := wit.ToAffGWitness(stmt)
	gstmt, err := stmt.ToAffGStatement()
	if err != nil {
		return nil, err
	}

	gproof, err := NewAffGProof(gwit, gstmt, rp)
	return gproof.ToAffGInvProof(), err
}

// aff-g from CGG21 Section 6.2 Figure 15.
func (proof *AffGInvProof) Verify(stmt *AffGInvStatement, rp *RingPedersenParams) bool {
	if proof == nil {
		return false
	}

	gproof := &proof.AffGProof
	gstmt, err := stmt.ToAffGStatement()
	if err != nil {
		return false
	}

	return gproof.Verify(gstmt, rp)
}

func (proof *AffGProof) ToAffGInvProof() *AffGInvProof {
	if proof == nil {
		return nil
	}
	return &AffGInvProof{AffGProof: *proof}
}

func (proof *AffGInvProof) IsNil() bool {
	return proof == nil
}

func (proof *AffGInvProof) Parts() int {
	return AffGProofParts
}

func (proof *AffGInvProof) Bytes() [][]byte {
	gproof := &proof.AffGProof
	return gproof.Bytes()
}

func (proof *AffGInvProof) NotNil() bool {
	if proof.IsNil() {
		return false
	}
	gproof := &proof.AffGProof
	return gproof.NotNil()
}

func (proof *AffGInvProof) ProofFromBytes(ec elliptic.Curve, bzs [][]byte) (Proof, error) {
	np, err := new(AffGProof).ProofFromBytes(ec, bzs)
	if err != nil {
		return nil, fmt.Errorf("could not read AffGInvProof")
	}
	newProof := np.(*AffGProof)
	return newProof.ToAffGInvProof(), nil
}
