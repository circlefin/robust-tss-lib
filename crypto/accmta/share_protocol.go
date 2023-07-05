// Copyright © 2023 Circle
//
// This file implements the accountable mta protocols

package accmta

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/crypto/paillier"
	"github.com/bnb-chain/tss-lib/crypto/zkproofs"
)

const (
	BobProofPParts  = zkproofs.AffPProofParts + 2
	BobProofDLParts = zkproofs.AffGProofParts + 1
)

type BobProofP struct {
	Proof *zkproofs.AffPProof
	X     *big.Int
	Y     *big.Int
}

type BobProofDL struct {
	Proof *zkproofs.AffGProof
	Y     *big.Int
}

func AliceInit(
	ec elliptic.Curve,
	// Alice public key
	pkA *paillier.PublicKey,
	// Alice secret
	a *big.Int,
	// Bob's Ring Pedersen parameters
	rpB *zkproofs.RingPedersenParams,
) (cA *big.Int, pf *zkproofs.EncProof, err error) {
	cA, rA, err := pkA.EncryptAndReturnRandomness(a)
	if err != nil {
		return nil, nil, err
	}
	witness := &zkproofs.EncWitness{
		K:   a,  // plaintext
		Rho: rA, // randomness
	}
	ell := zkproofs.GetEll(ec)
	statement := &zkproofs.EncStatement{
		K:  cA,    // ciphertext
		N0: pkA.N, // public key to ciphertext
		EC: ec,    // elliptic curve
	}

	pf, err = zkproofs.NewEncProof(witness, statement, rpB)
	if err != nil {
		return nil, nil, err
	}
	if !zkproofs.NewEll(ell).InRange(a) {
		err = errors.New("a out of range")
		return nil, nil, err
	}
	if !pf.Verify(statement, rpB) {
		err = errors.New("bad proof")
		return nil, nil, err
	}
	return cA, pf, nil
}

func BobRespondsP(
	ec elliptic.Curve,
	// Alice's public key
	pkA *paillier.PublicKey,
	// Bob's public key
	pkB *paillier.PublicKey,
	// Alice's proof
	proofAlice *zkproofs.EncProof,
	// Bob's secret
	b *big.Int,
	// Alice's encryption of a under pkA
	cA *big.Int,
	// Alice's Ring Pedersen parameters
	rpA *zkproofs.RingPedersenParams,
	// Bob's Ring Pedersen parameters
	rpB *zkproofs.RingPedersenParams,
) (beta, cB, betaPrm *big.Int, piB *BobProofP, err error) {
	if !BobVerify(ec, pkA, proofAlice, cA, rpB) {
		err = errors.New("RangeProofAlice.Verify() returned false")
		return
	}

	// Compute response
	// TODO: what is correct size for betaPrm? AffPProof Fig 26 needs
	// it to be in 2^ell, but does share conversion require a bigger betaPrm?
	betaPrm = common.GetRandomPositiveInt(ec.Params().N)
	X, rhox, err := pkB.EncryptAndReturnRandomness(b)
	Y, rhoy, err := pkB.EncryptAndReturnRandomness(betaPrm)
	if err != nil {
		return
	}
	cB, err = pkA.HomoMult(b, cA)
	if err != nil {
		return
	}
	cB, err = pkA.HomoAddInt(betaPrm, cB)
	if err != nil {
		return
	}
	witness := &zkproofs.AffPWitness{
		X:    b,             // Bob's secret input plaintext of X
		Y:    betaPrm,       // plaintext for ciphertext Y
		Rhox: rhox,          // randomness for ciphertext X
		Rhoy: rhoy,          // randomness for ciphertext Y
		Rho:  big.NewInt(1), // affine transform does not add any randomness to cB
	}
	statement := &zkproofs.AffPStatement{
		C:        cA,                  // Alice's ciphertext
		D:        cB,                  // affine transform of Alice's ciphertext: cA(*)b + betaPrm
		X:        X,                   // encryption of b using Bob's public key
		Y:        Y,                   // encryption of betaPrm
		N0:       pkA.N,               // Alice's public key
		N1:       pkB.N,               // Bob's public key
		Ell:      zkproofs.GetEll(ec), // max size of plaintext
		EllPrime: zkproofs.GetEll(ec), // max size of plaintext
		EC:       ec,                  // elliptic curve
	}
	proof, err := zkproofs.NewAffPProof(witness, statement, rpA)
	if err != nil {
		return
	}
	piB = &BobProofP{
		Proof: proof,
		X:     X,
		Y:     Y,
	}

	// beta = -betaPrm mod q
	q := ec.Params().N
	beta = common.ModInt(q).Sub(big.NewInt(0), betaPrm)
	return
}

func BobVerify(
	ec elliptic.Curve,
	// Alice's public key
	pkA *paillier.PublicKey,
	// Alice's proof
	proofAlice *zkproofs.EncProof,
	// Alice's encryption of a under pkA
	cA *big.Int,
	// Bob's Ring Pedersen parameters
	rpB *zkproofs.RingPedersenParams,
) bool {
	// check Alice's proof
	statementA := &zkproofs.EncStatement{
		K:  cA,    // Alice's ciphertext
		N0: pkA.N, // Alice's public key
		EC: ec,    // max size of plaintext
	}
	return proofAlice.Verify(statementA, rpB)
}

func BobRespondsDL(
	ec elliptic.Curve,
	// Alice's public key
	pkA *paillier.PublicKey,
	// Bob's public key
	pkB *paillier.PublicKey,
	// Alice's proof
	proofAlice *zkproofs.EncProof,
	// Bob's secret
	b *big.Int,
	// Alice's encryption of a under pkA
	cA *big.Int,
	// Alice's Ring Pedersen parameters
	rpA *zkproofs.RingPedersenParams,
	// Bob's Ring Pedersen parameters
	rpB *zkproofs.RingPedersenParams,
	// DL commitment to Bob's input b
	B *crypto.ECPoint,
) (beta, cB, betaPrm *big.Int, piB *BobProofDL, err error) {
	if !BobVerify(ec, pkA, proofAlice, cA, rpB) {
		err = errors.New("RangeProofAlice.Verify() returned false")
		return
	}

	// Compute response
	// TODO: what is correct size for betaPrm? AffPProof Fig 26 needs
	// it to be in 2^ell, but does share conversion require a bigger betaPrm?
	betaPrm = common.GetRandomPositiveInt(ec.Params().N)
	Y, rhoy, err := pkB.EncryptAndReturnRandomness(betaPrm)
	if err != nil {
		return
	}
	cB, err = pkA.HomoMult(b, cA)
	if err != nil {
		return
	}
	cB, err = pkA.HomoAddInt(betaPrm, cB)
	if err != nil {
		return
	}
	witness := &zkproofs.AffGWitness{
		X:    b,             // Bob's secret input plaintext of X
		Y:    betaPrm,       // plaintext for ciphertext Y
		Rhoy: rhoy,          // randomness for ciphertext Y
		Rho:  big.NewInt(1), // affine transform does not add any randomness to cB
	}
	statement := &zkproofs.AffGStatement{
		C:        cA,                  // Alice's ciphertext
		D:        cB,                  // affine transform of Alice's ciphertext: cA(*)b + betaPrm
		X:        B,                   // B = g^b is a DL commitment to Bob's input b
		Y:        Y,                   // encryption of betaPrm
		N0:       pkA.N,               // Alice's public key
		N1:       pkB.N,               // Bob's public key
		Ell:      zkproofs.GetEll(ec), // max size of plaintext
		EllPrime: zkproofs.GetEll(ec), // max size of plaintext
	}

	proof, err := zkproofs.NewAffGProof(witness, statement, rpA)
	if err != nil {
		return
	}
	piB = &BobProofDL{
		Proof: proof,
		Y:     Y,
	}
	if piB == nil {
		err = errors.New("piB nil")
		return
	}

	// beta = -betaPrm mod q
	// beta = -betaPrm mod q
	q := ec.Params().N
	beta = common.ModInt(q).Sub(big.NewInt(0), betaPrm)
	return
}

func AliceEndP(
	ec elliptic.Curve,
	// Alice's Paillier keys
	skA *paillier.PrivateKey,
	// Bob's Paillier keys
	pkB *paillier.PublicKey,
	// Bob's proof
	proof *BobProofP,
	// Statement
	cA, cB *big.Int,
	// Alice's Ring Pedersen parameters
	rpA *zkproofs.RingPedersenParams,
) (*big.Int, error) {
	statement := &zkproofs.AffPStatement{
		C:        cA,                  // Alice's ciphertext
		D:        cB,                  // affine transform of Alice's ciphertext: cA(*)b + betaPrm
		X:        proof.X,             // encryption of b using Bob's public key
		Y:        proof.Y,             // encryption of betaPrm
		N0:       skA.PublicKey.N,     // Alice's public key
		N1:       pkB.N,               // Bob's public key
		Ell:      zkproofs.GetEll(ec), // max size of plaintext
		EllPrime: zkproofs.GetEll(ec), // max size of plaintext
		EC:       ec,                  // elliptic curve
	}
	if !proof.Proof.Verify(statement, rpA) {
		return nil, errors.New("AffPProof.Verify() returned false")
	}
	alphaPrm, err := skA.Decrypt(cB)
	if err != nil {
		return nil, err
	}
	q := ec.Params().N
	return new(big.Int).Mod(alphaPrm, q), nil
}

func AliceEndDL(
	ec elliptic.Curve,
	// Alice's Paillier keys
	skA *paillier.PrivateKey,
	// Bob's Paillier keys
	pkB *paillier.PublicKey,
	// Bob's proof
	proof *BobProofDL,
	// Statement
	cA, cB *big.Int,
	B *crypto.ECPoint,
	// Alice's Ring Pedersen parameters
	rpA *zkproofs.RingPedersenParams,
) (*big.Int, error) {
	statement := &zkproofs.AffGStatement{
		C:        cA,                  // Alice's ciphertext
		D:        cB,                  // affine transform of Alice's ciphertext: cA(*)b + betaPrm
		X:        B,                   // B = g^b is a DL commitment to Bob's input b
		Y:        proof.Y,             // encryption of betaPrm
		N0:       skA.PublicKey.N,     // Alice's public key
		N1:       pkB.N,               // Bob's public key
		Ell:      zkproofs.GetEll(ec), // max size of plaintext
		EllPrime: zkproofs.GetEll(ec), // max size of plaintext
	}
	if !proof.Proof.Verify(statement, rpA) {
		return nil, errors.New("AffGProof.Verify() returned false")
	}
	alphaPrm, err := skA.Decrypt(cB)
	if err != nil {
		return nil, err
	}
	q := ec.Params().N
	return new(big.Int).Mod(alphaPrm, q), nil
}

func (proof *BobProofP) Bytes() [BobProofPParts][]byte {
	proofBytes := proof.Proof.Bytes()
	var output [BobProofPParts][]byte
	for index := 0; index < zkproofs.AffPProofParts; index++ {
		output[index] = proofBytes[index]
	}
	output[zkproofs.AffPProofParts] = proof.X.Bytes()
	output[zkproofs.AffPProofParts+1] = proof.Y.Bytes()

	return output
}

func BobProofPFromBytes(bzs [][]byte) (*BobProofP, error) {
	if !common.NonEmptyMultiBytes(bzs, BobProofPParts) {
		return nil, fmt.Errorf("expected %d byte parts to construct BobProofP", BobProofPParts)
	}
	var proofBytes [zkproofs.AffPProofParts][]byte
	for index := 0; index < zkproofs.AffPProofParts; index++ {
		proofBytes[index] = bzs[index]
	}
	proof, err := zkproofs.AffPProofFromBytes(proofBytes[:])
	if err != nil {
		return nil, err
	}
	return &BobProofP{
		Proof: proof,
		X:     new(big.Int).SetBytes(bzs[zkproofs.AffPProofParts]),
		Y:     new(big.Int).SetBytes(bzs[zkproofs.AffPProofParts+1]),
	}, nil
}

func (proof *BobProofDL) Bytes() [BobProofDLParts][]byte {
	proofBytes := proof.Proof.Bytes()
	var output [BobProofDLParts][]byte
	for index := 0; index < zkproofs.AffGProofParts; index++ {
		output[index] = proofBytes[index]
	}
	output[zkproofs.AffGProofParts] = proof.Y.Bytes()

	return output
}

func BobProofDLFromBytes(ec elliptic.Curve, bzs [][]byte) (*BobProofDL, error) {
	if !common.NonEmptyMultiBytes(bzs, BobProofDLParts) {
		return nil, fmt.Errorf("expected %d byte parts to construct BobProofDL", BobProofDLParts)
	}
	var proofBytes [zkproofs.AffGProofParts][]byte
	for index := 0; index < zkproofs.AffGProofParts; index++ {
		proofBytes[index] = bzs[index]
	}
	proof, err := zkproofs.AffGProofFromBytes(ec, proofBytes[:])
	if err != nil {
		return nil, err
	}
	return &BobProofDL{
		Proof: proof,
		Y:     new(big.Int).SetBytes(bzs[zkproofs.AffGProofParts]),
	}, nil
}
