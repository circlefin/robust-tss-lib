// Copyright © 2023 Circle
//
// This file implements the accountable mta protocols

package accmta

import (
	"crypto/elliptic"
	"errors"
	"math/big"
	"sync"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/crypto/paillier"
	"github.com/bnb-chain/tss-lib/crypto/zkproofs"
)

func AliceInit(
	ec elliptic.Curve,
	// Alice public key
	pkA *paillier.PublicKey,
	// Alice secret
	a, rA *big.Int,
	// Verifier Ring Pedersen parameters
	rpV []*zkproofs.RingPedersenParams,
) (*big.Int, []*zkproofs.EncProof, error) {
	ell := zkproofs.GetEll(ec)
	if !zkproofs.NewEll(ell).InRange(a) {
		err := errors.New("a out of range")
		return nil, nil, err
	}

	cA, err := pkA.EncryptWithRandomness(a, rA)
	if err != nil {
		return nil, nil, err
	}
	witness := &zkproofs.EncWitness{
		K:   a,  // plaintext
		Rho: rA, // randomness
	}
	statement := &zkproofs.EncStatement{
		K:  cA,    // ciphertext
		N0: pkA.N, // public key to ciphertext
		EC: ec,    // elliptic curve
	}

	wg := sync.WaitGroup{}
	wg.Add(len(rpV))
	proofs := make([]*zkproofs.EncProof, len(rpV))
	err = nil
	for i, rp := range rpV {
		go func(i int, rp *zkproofs.RingPedersenParams) {
			defer wg.Done()
			if rp == nil {
				proofs[i] = nil
				return
			}
			proofs[i], err = zkproofs.NewEncProof(witness, statement, rp)
		}(i, rp)
	}
	wg.Wait()
	if err != nil {
		return nil, nil, err
	}
	return cA, proofs, nil
}

func BobRespondsP(
	ec elliptic.Curve,
	// Alice's public key
	pkA *paillier.PublicKey,
	// Bob's public key
	skB *paillier.PrivateKey,
	// Alice's proof
	proofAlice *zkproofs.EncProof,
	// Bob's encryption of his secret
	cB,
	// Alice's encryption of a under pkA
	cA *big.Int,
	// Verifier Ring Pedersen parameters
	rpV []*zkproofs.RingPedersenParams,
	// Bob's Ring Pedersen parameters
	rpB *zkproofs.RingPedersenParams,
) (beta, cAlpha, cBeta, cBetaPrm *big.Int, proofs []*zkproofs.AffPProof, decProofs []*zkproofs.DecProof, err error) {
	if !BobVerify(ec, pkA, proofAlice, cA, rpB) {
		err = errors.New("RangeProofAlice.Verify() returned false")
		return
	}

	// Compute response
	// TODO: what is correct size for betaPrm? AffPProof Fig 26 needs
	// it to be in 2^ell, but does share conversion require a bigger betaPrm?
	q := ec.Params().N
	betaPrm := common.GetRandomPositiveInt(q)
	b, rhox, err := skB.DecryptFull(cB)
	if err != nil {
		return
	}
	cBetaPrm, rhoy, err := skB.PublicKey.EncryptAndReturnRandomness(betaPrm)
	if err != nil {
		return
	}
	cAlpha, err = pkA.HomoMult(b, cA)
	if err != nil {
		return
	}
	cAlpha, err = pkA.HomoAddInt(betaPrm, cAlpha)
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
		D:        cAlpha,              // affine transform of Alice's ciphertext: cA(*)b + betaPrm
		X:        cB,                  // encryption of b using Bob's public key
		Y:        cBetaPrm,            // encryption of betaPrm
		N0:       pkA.N,               // Alice's public key
		N1:       skB.PublicKey.N,     // Bob's public key
		Ell:      zkproofs.GetEll(ec), // max size of plaintext
		EllPrime: zkproofs.GetEll(ec), // max size of plaintext
		EC:       ec,                  // elliptic curve
	}

	beta = common.ModInt(q).Sub(big.NewInt(0), betaPrm)
	cBeta, err = skB.PublicKey.Encrypt(beta)
	if err != nil {
		return
	}
	decProofs, err = DecProofs(skB, ec, cBeta, cBetaPrm, rpV)
	if err != nil {
		return
	}

	wg := sync.WaitGroup{}
	wg.Add(len(rpV))
	proofs = make([]*zkproofs.AffPProof, len(rpV))
	for i, rp := range rpV {
		go func(i int, rp *zkproofs.RingPedersenParams) {
			defer wg.Done()
			if rp == nil {
				proofs[i] = nil
				return
			}
			proofs[i], _ = zkproofs.NewAffPProof(witness, statement, rp)
		}(i, rp)
	}
	wg.Wait()

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
	// Verifier's Ring Pedersen parameters
	rpV *zkproofs.RingPedersenParams,
) bool {
	// check Alice's proof
	statementA := &zkproofs.EncStatement{
		K:  cA,    // Alice's ciphertext
		N0: pkA.N, // Alice's public key
		EC: ec,    // max size of plaintext
	}
	return proofAlice.Verify(statementA, rpV)
}

func BobRespondsDL(
	ec elliptic.Curve,
	// Alice's public key
	pkA *paillier.PublicKey,
	// Bob's public key
	skB *paillier.PrivateKey,
	// Alice's proof
	proofAlice *zkproofs.EncProof,
	// Bob's secret
	b *big.Int,
	// Alice's encryption of a under pkA
	cA *big.Int,
	// Verifier's Ring Pedersen parameters
	rpV []*zkproofs.RingPedersenParams,
	// Bob's Ring Pedersen parameters
	rpB *zkproofs.RingPedersenParams,
	// DL commitment to Bob's input b
	B *crypto.ECPoint,
) (beta, cAlpha, cBeta, cBetaPrm *big.Int, proofs []*zkproofs.AffGProof, decProofs []*zkproofs.DecProof, err error) {
	if !BobVerify(ec, pkA, proofAlice, cA, rpB) {
		err = errors.New("RangeProofAlice.Verify() returned false")
		return
	}

	// Compute response
	// TODO: what is correct size for betaPrm? AffPProof Fig 26 needs
	// it to be in 2^ell, but does share conversion require a bigger betaPrm?
	q := ec.Params().N
	betaPrm := common.GetRandomPositiveInt(q)
	beta = common.ModInt(q).Sub(big.NewInt(0), betaPrm)
	cBetaPrm, rhoy, err := skB.PublicKey.EncryptAndReturnRandomness(betaPrm)
	if err != nil {
		return
	}
	cAlpha, err = pkA.HomoMult(b, cA)
	if err != nil {
		return
	}
	cAlpha, err = pkA.HomoAddInt(betaPrm, cAlpha)
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
		D:        cAlpha,              // affine transform of Alice's ciphertext: cA(*)b + betaPrm
		X:        B,                   // B = g^b is a DL commitment to Bob's input b
		Y:        cBetaPrm,            // encryption of betaPrm
		N0:       pkA.N,               // Alice's public key
		N1:       skB.PublicKey.N,     // Bob's public key
		Ell:      zkproofs.GetEll(ec), // max size of plaintext
		EllPrime: zkproofs.GetEll(ec), // max size of plaintext
	}

	beta = common.ModInt(q).Sub(big.NewInt(0), betaPrm)
	cBeta, err = skB.PublicKey.Encrypt(beta)
	if err != nil {
		return
	}
	decProofs, err = DecProofs(skB, ec, cBeta, cBetaPrm, rpV)
	if err != nil {
		return
	}

	wg := sync.WaitGroup{}
	wg.Add(len(rpV))
	proofs = make([]*zkproofs.AffGProof, len(rpV))
	for i, rp := range rpV {
		go func(i int, rp *zkproofs.RingPedersenParams) {
			defer wg.Done()
			if rp == nil {
				proofs[i] = nil
				return
			}
			proof, err := zkproofs.NewAffGProof(witness, statement, rp)
			if err != nil {
				return
			}
			proofs[i] = proof
		}(i, rp)
	}
	wg.Wait()
	return
}

func BobRespondsG(
	ec elliptic.Curve,
	// Alice's public key
	pkA *paillier.PublicKey,
	// Bob's public key
	skB *paillier.PrivateKey,
	// Alice's proof
	proofAlice *zkproofs.EncProof,
	// Bob's secret
	b *big.Int,
	// Alice's encryption of a under pkA
	cA *big.Int,
	// Verifier's Ring Pedersen parameters
	rpV []*zkproofs.RingPedersenParams,
	// Bob's Ring Pedersen parameters
	rpB *zkproofs.RingPedersenParams,
) (beta, cAlpha, cBeta *big.Int, proofs []*zkproofs.AffGInvProof, err error) {
	if !BobVerify(ec, pkA, proofAlice, cA, rpB) {
		err = errors.New("RangeProofBob.Verify() returned false")
		return
	}

	// Compute response
	// TODO: what is correct size for betaPrm? AffPProof Fig 26 needs
	// it to be in 2^ell, but does share conversion require a bigger betaPrm?
	q := ec.Params().N
	beta = common.GetRandomPositiveInt(q)

	witness, statement, err := zkproofs.NewAffGInvWitness(ec, skB, pkA, b, beta, cA)
	cAlpha = statement.D
	cBeta = statement.Y

	wg := sync.WaitGroup{}
	wg.Add(len(rpV))
	proofs = make([]*zkproofs.AffGInvProof, len(rpV))
	for i, rp := range rpV {
		go func(i int, rp *zkproofs.RingPedersenParams) {
			defer wg.Done()
			if rp == nil {
				proofs[i] = nil
				return
			}
			proof, err := zkproofs.NewAffGInvProof(witness, statement, rp)
			if err != nil {
				return
			}
			proofs[i] = proof
		}(i, rp)
	}
	wg.Wait()
	return
}


func AliceEndP(
	ec elliptic.Curve,
	// Alice's Paillier keys
	skA *paillier.PrivateKey,
	// Bob's Paillier keys
	pkB *paillier.PublicKey,
	// Bob's proof
	proof *zkproofs.AffPProof,
	decproof *zkproofs.DecProof,
	// Statement
	cA, cAlpha, cBeta, cBetaPrm, cB *big.Int,
	// Alice's Ring Pedersen parameters
	rpA *zkproofs.RingPedersenParams,
) (*big.Int, error) {
	if !AliceVerifyP(ec, &skA.PublicKey, pkB, proof, cA, cAlpha, cBetaPrm, cB, rpA) {
		return nil, errors.New("AffPProof.Verify() returned false")
	}
	if !DecProofVerify(pkB, ec, decproof, cBeta, cBetaPrm, rpA) {
		return nil, errors.New("DecProof.Verify() returned false")
	}
	alphaPrm, err := skA.Decrypt(cAlpha)
	if err != nil {
		return nil, err
	}
	q := ec.Params().N
	return new(big.Int).Mod(alphaPrm, q), nil
}

func AliceVerifyP(
	ec elliptic.Curve,
	// Alice's Paillier keys
	pkA *paillier.PublicKey,
	// Bob's Paillier keys
	pkB *paillier.PublicKey,
	// Bob's proof
	proof *zkproofs.AffPProof,
	// Statement
	cA, cAlpha, cBetaPrm, cB *big.Int,
	// Verifier's Ring Pedersen parameters
	rpV *zkproofs.RingPedersenParams,
) bool {
	if rpV == nil {
		return true
	}
	statement := &zkproofs.AffPStatement{
		C:        cA,                  // Alice's ciphertext
		D:        cAlpha,              // affine transform of Alice's ciphertext: cA(*)b + betaPrm
		X:        cB,                  // encryption of b using Bob's public key
		Y:        cBetaPrm,            // encryption of betaPrm
		N0:       pkA.N,               // Alice's public key
		N1:       pkB.N,               // Bob's public key
		Ell:      zkproofs.GetEll(ec), // max size of plaintext
		EllPrime: zkproofs.GetEll(ec), // max size of plaintext
		EC:       ec,                  // elliptic curve
	}
	if !proof.Verify(statement, rpV) {
		return false
	}
	return true
}

func AliceEndDL(
	ec elliptic.Curve,
	// Alice's Paillier keys
	skA *paillier.PrivateKey,
	// Bob's Paillier keys
	pkB *paillier.PublicKey,
	// Bob's proof
	proof *zkproofs.AffGProof,
	decproof *zkproofs.DecProof,
	// Statement
	cA, cAlpha, cBeta, cBetaPrm *big.Int,
	B *crypto.ECPoint,
	// Alice's Ring Pedersen parameters
	rpA *zkproofs.RingPedersenParams,
) (*big.Int, error) {
	if !AliceVerifyDL(ec, &skA.PublicKey, pkB, proof, cA, cAlpha, cBetaPrm, B, rpA) {
		return nil, errors.New("AffGProof.Verify() returned false")
	}

	if !DecProofVerify(pkB, ec, decproof, cBeta, cBetaPrm, rpA) {
		return nil, errors.New("DecProof.Verify() returned false")
	}

	alphaPrm, err := skA.Decrypt(cAlpha)
	if err != nil {
		return nil, err
	}
	q := ec.Params().N
	return new(big.Int).Mod(alphaPrm, q), nil
}

func AliceVerifyDL(
	ec elliptic.Curve,
	// Alice's Paillier keys
	pkA *paillier.PublicKey,
	// Bob's Paillier keys
	pkB *paillier.PublicKey,
	// Bob's proof
	proof *zkproofs.AffGProof,
	// Statement
	cA, cAlpha, cBetaPrm *big.Int,
	B *crypto.ECPoint,
	// Verifier's Ring Pedersen parameters
	rpV *zkproofs.RingPedersenParams,
) bool {
	if rpV == nil {
		return true
	}
	statement := &zkproofs.AffGStatement{
		C:        cA,                  // Alice's ciphertext
		D:        cAlpha,              // affine transform of Alice's ciphertext: cA(*)b + betaPrm
		X:        B,                   // B = g^b is a DL commitment to Bob's input b
		Y:        cBetaPrm,            // encryption of betaPrm
		N0:       pkA.N,               // Alice's public key
		N1:       pkB.N,               // Bob's public key
		Ell:      zkproofs.GetEll(ec), // max size of plaintext
		EllPrime: zkproofs.GetEll(ec), // max size of plaintext
	}

	return proof.Verify(statement, rpV)
}

func AliceEndG(
	ec elliptic.Curve,
	// Alice's Paillier keys
	skA *paillier.PrivateKey,
	// Bob's Paillier keys
	pkB *paillier.PublicKey,
	// Bob's proof
	proof *zkproofs.AffGInvProof,
	// Statement
	cA, cAlpha, cBeta *big.Int,
	B *crypto.ECPoint,
	// Alice's Ring Pedersen parameters
	rpA *zkproofs.RingPedersenParams,
) (*big.Int, error) {
	if !AliceVerifyG(ec, &skA.PublicKey, pkB, proof, cA, cAlpha, cBeta, B, rpA) {
		return nil, errors.New("AffGInvProof.Verify() returned false")
	}

	alphaPrm, err := skA.Decrypt(cAlpha)
	if err != nil {
		return nil, err
	}
	q := ec.Params().N
	return new(big.Int).Mod(alphaPrm, q), nil
}

func AliceVerifyG(
	ec elliptic.Curve,
	// Alice's Paillier keys
	pkA *paillier.PublicKey,
	// Bob's Paillier keys
	pkB *paillier.PublicKey,
	// Bob's proof
	proof *zkproofs.AffGInvProof,
	// Statement
	cA, cAlpha, cBeta *big.Int,
	B *crypto.ECPoint,
	// Verifier's Ring Pedersen parameters
	rpV *zkproofs.RingPedersenParams,
) bool {
	if rpV == nil {
		return true
	}
	statement := &zkproofs.AffGInvStatement{
		zkproofs.AffGStatement{
		C:        cA,                  // Alice's ciphertext
		D:        cAlpha,              // affine transform of Alice's ciphertext: cA(*)b + betaPrm
		X:        B,                   // B = g^b is a DL commitment to Bob's input b
		Y:        cBeta,               // encryption of betaPrm
		N0:       pkA.N,               // Alice's public key
		N1:       pkB.N,               // Bob's public key
		Ell:      zkproofs.GetEll(ec), // max size of plaintext
		EllPrime: zkproofs.GetEll(ec), // max size of plaintext
		},
	}

	return proof.Verify(statement, rpV)
}



func DecProofs(sk *paillier.PrivateKey, ec elliptic.Curve, cBeta, cBetaPrm *big.Int, rpV []*zkproofs.RingPedersenParams) ([]*zkproofs.DecProof, error) {
	cQ, err := sk.PublicKey.HomoAdd(cBeta, cBetaPrm)
	if err != nil {
		return nil, err
	}

	dQ, rho, err := sk.DecryptFull(cQ)
	if err != nil {
		return nil, err
	}

	statement := &zkproofs.DecStatement{
		Q:   ec.Params().N,
		Ell: zkproofs.GetEll(ec),
		N0:  sk.PublicKey.N,
		C:   cQ,
		X:   big.NewInt(0),
	}
	witness := &zkproofs.DecWitness{
		Y:   dQ,
		Rho: rho,
	}
	proofs := make([]*zkproofs.DecProof, len(rpV))

	wg := sync.WaitGroup{}
	wg.Add(len(rpV))
	proofs = make([]*zkproofs.DecProof, len(rpV))
	for i, rp := range rpV {
		go func(i int, rp *zkproofs.RingPedersenParams) {
			defer wg.Done()
			if rp == nil {
				proofs[i] = nil
				return
			}
			proofs[i] = zkproofs.NewDecProof(witness, statement, rp)
		}(i, rp)
	}
	wg.Wait()
	return proofs, nil
}

func DecProofVerify(pk *paillier.PublicKey, ec elliptic.Curve, proof *zkproofs.DecProof, cBeta, cBetaPrm *big.Int, rp *zkproofs.RingPedersenParams) bool {
	if rp == nil {
		return true
	}

	cQ, err := pk.HomoAdd(cBeta, cBetaPrm)
	if err != nil {
		return false
	}
	statement := &zkproofs.DecStatement{
		Q:   ec.Params().N,
		Ell: zkproofs.GetEll(ec),
		N0:  pk.N,
		C:   cQ,
		X:   big.NewInt(0),
	}

	return proof.Verify(statement, rp)
}
