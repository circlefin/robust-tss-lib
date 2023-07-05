// Copyright 2023 Circle

package accmta_test

import (
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/crypto/accmta"
	"github.com/bnb-chain/tss-lib/crypto/paillier"
	"github.com/bnb-chain/tss-lib/crypto/zkproofs"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/tss"
)

var (
	skA, skB *paillier.PrivateKey
	pkA, pkB *paillier.PublicKey
	rpA, rpB *zkproofs.RingPedersenParams
	ec       elliptic.Curve
	q        *big.Int
	ell      *big.Int
)

func setUp(t *testing.T) {
	ec = tss.EC()
	q = ec.Params().N
	ell = zkproofs.GetEll(ec)
	assert.NotNil(t, ell)

	var err error
	skA, pkA, rpA, err = GetSavedKeys(0)
	assert.NoError(t, err)
	skB, pkB, rpB, err = GetSavedKeys(1)
	assert.NoError(t, err)
}

func GetSavedKeys(idx int) (sk *paillier.PrivateKey, pk *paillier.PublicKey, rp *zkproofs.RingPedersenParams, err error) {
	fixtures, _, err := keygen.LoadKeygenTestFixtures(idx + 1)
	if err != nil {
		return
	}
	fixture := fixtures[idx]
	rp = &zkproofs.RingPedersenParams{
		N: fixture.NTildei,
		S: fixture.H1i,
		T: fixture.H2i,
	}
	sk = fixture.PaillierSK
	pk = &paillier.PublicKey{N: sk.N}
	return
}

func TestMTA_P(t *testing.T) {
	setUp(t)

	a := common.GetRandomPositiveInt(q)
	b := common.GetRandomPositiveInt(q)

	cA, pf, err := accmta.AliceInit(ec, pkA, a, rpB)
	assert.NoError(t, err)
	assert.NotNil(t, pf)
	assert.NotNil(t, cA)
	statementA := &zkproofs.EncStatement{
		K:  cA,    // Alice's ciphertext
		N0: pkA.N, // Alice's public key
		EC: ec,    // max size of plaintext
	}
	verify := pf.Verify(statementA, rpB)
	assert.True(t, verify)

	beta, cB, betaPrm, piB, err := accmta.BobRespondsP(ec, pkA, pkB, pf, b, cA, rpA, rpB)
	assert.NoError(t, err)
	assert.NotNil(t, piB)
	assert.NotNil(t, piB.X)
	assert.NotNil(t, piB.Y)

	alpha, err := accmta.AliceEndP(ec, skA, pkB, piB, cA, cB, rpA)
	assert.NotNil(t, alpha)
	assert.NoError(t, err)

	// expect: alpha = ab + betaPrm
	right2 := new(big.Int).Mod(zkproofs.APlusBC(betaPrm, a, b), q)
	assert.Equal(t, 0, alpha.Cmp(right2))

	// expect alpha + beta = a*b
	left1 := common.ModInt(q).Add(alpha, beta)
	right1 := common.ModInt(q).Mul(a, b)
	assert.Equal(t, 0, left1.Cmp(right1))
}

func TestMTA_DL(t *testing.T) {
	setUp(t)

	a := common.GetRandomPositiveInt(q)
	b := common.GetRandomPositiveInt(q)

	cA, pf, err := accmta.AliceInit(ec, pkA, a, rpB)
	assert.NoError(t, err)
	assert.NotNil(t, pf)
	assert.NotNil(t, cA)

	B := crypto.ScalarBaseMult(ec, b)
	assert.NoError(t, err)
	beta, cB, betaPrm, piB, err := accmta.BobRespondsDL(ec, pkA, pkB, pf, b, cA, rpA, rpB, B)
	assert.NoError(t, err)
	assert.NotNil(t, piB)
	assert.NotNil(t, piB.Y)

	alpha, err := accmta.AliceEndDL(ec, skA, pkB, piB, cA, cB, B, rpA)
	assert.NotNil(t, alpha)
	assert.NoError(t, err)

	// expect: alpha = ab + betaPrm
	aTimesB := new(big.Int).Mul(a, b)
	aTimesBPlusBeta := new(big.Int).Add(aTimesB, betaPrm)
	aTimesBPlusBetaModQ := new(big.Int).Mod(aTimesBPlusBeta, q)
	assert.Equal(t, 0, alpha.Cmp(aTimesBPlusBetaModQ))

	// expect alpha + beta = a*b
	left1 := common.ModInt(q).Add(alpha, beta)
	right1 := common.ModInt(q).Mul(a, b)
	assert.Equal(t, 0, left1.Cmp(right1))
}

func GenerateAffGData(t *testing.T) (*zkproofs.AffGWitness, *zkproofs.AffGStatement) {
	N := pkB.N
	N2 := new(big.Int).Mul(N, N)

	// Specifically,the Prover has secret input (x, y, rho, rhox, rhoy) such that
	c := common.GetRandomPositiveInt(q)
	x := common.GetRandomPositiveInt(q)
	y := common.GetRandomPositiveInt(q)
	rho := common.GetRandomPositiveInt(q)
	rhoy := common.GetRandomPositiveInt(q)
	witness := &zkproofs.AffGWitness{
		X:    x,
		Y:    y,
		Rho:  rho,
		Rhoy: rhoy,
	}

	// X = g^x
	X := crypto.ScalarBaseMult(ec, witness.X)
	//  Y = (1+N1)^y * rhoy^N1 mod N1^2
	Y, _ := pkB.EncryptWithRandomness(y, rhoy)
	//  D  = C^x * (1+N0)^y * rho^N0 mod N0^2
	C, _ := pkB.Encrypt(c)
	Dprime, _ := pkB.EncryptWithRandomness(y, rho)
	D := zkproofs.ATimesBToTheCModN(Dprime, C, x, N2)
	statement := &zkproofs.AffGStatement{
		C:        C,
		D:        D,
		X:        X,
		Y:        Y,
		N0:       pkB.N,
		N1:       pkB.N,
		Ell:      ell,
		EllPrime: ell,
	}
	return witness, statement
}

func GenerateAffPData(t *testing.T) (*zkproofs.AffPWitness, *zkproofs.AffPStatement) {
	N02 := new(big.Int).Mul(pkA.N, pkA.N)

	// Specifically,the Prover has secret input (x, y, rho, rhox, rhoy) such that
	x := common.GetRandomPositiveInt(q)
	y := common.GetRandomPositiveInt(q)
	rho := common.GetRandomPositiveInt(q) //common.GetRandomPositiveInt(big.NewInt(1))
	rhox := common.GetRandomPositiveInt(pkB.N)
	rhoy := common.GetRandomPositiveInt(pkB.N)
	witness := &zkproofs.AffPWitness{
		X:    x,
		Y:    y,
		Rho:  rho,
		Rhox: rhox,
		Rhoy: rhoy,
	}

	//  C = PaillierEncrypt(N0, random)
	C := common.GetRandomPositiveInt(N02)
	//  D  = C^x * (1+N0)^y * rho^N0 mod N0^2
	Dprime, err := pkA.EncryptWithRandomness(y, rho)
	assert.NoError(t, err)
	D := zkproofs.ATimesBToTheCModN(Dprime, C, x, N02)
	//  X = (1+N1)^x * rhox^N1 mod N1^2
	X, _ := pkB.EncryptWithRandomness(x, rhox)
	//  Y = (1+N1)^y * rhoy^N1 mod N1^2
	Y, _ := pkB.EncryptWithRandomness(y, rhoy)
	statement := &zkproofs.AffPStatement{
		C:        C,
		D:        D,
		X:        X,
		Y:        Y,
		N0:       pkA.N,
		N1:       pkB.N,
		Ell:      ell,
		EllPrime: ell,
		EC:       ec,
	}
	return witness, statement
}

func TestBobProofPBytes(t *testing.T) {
	setUp(t)
	witness, statement := GenerateAffPData(t)
	proof, err := zkproofs.NewAffPProof(witness, statement, rpA)
	assert.NoError(t, err, "could not create NewAffGProof")
	bobProof := &accmta.BobProofP{
		Proof: proof,
		X:     statement.X,
		Y:     statement.Y,
	}
	bobProofBytes := bobProof.Bytes()
	var proofInBytes [][]byte = bobProofBytes[:]
	newProof, err := accmta.BobProofPFromBytes(proofInBytes)
	assert.NoError(t, err, "could not create NewAffPProof")
	assert.NotNil(t, newProof, "NewAffPProof nil")
	assert.False(t, newProof.Proof.Nil(), "proof has nil fields")
	assert.Equal(t, statement.Y, newProof.Y)
	assert.True(t, newProof.Proof.Verify(statement, rpA))
}

func TestBobProofDLBytes(t *testing.T) {
	setUp(t)
	witness, statement := GenerateAffGData(t)
	proof, err := zkproofs.NewAffGProof(witness, statement, rpA)
	assert.NoError(t, err, "could not create NewAffGProof")
	bobProof := &accmta.BobProofDL{
		Proof: proof,
		Y:     statement.Y,
	}
	bobProofBytes := bobProof.Bytes()
	var proofInBytes [][]byte = bobProofBytes[:]
	newProof, err := accmta.BobProofDLFromBytes(ec, proofInBytes)
	assert.NoError(t, err, "could not create NewAffGProof")
	assert.NotNil(t, newProof, "NewAffGProof nil")
	assert.False(t, newProof.Proof.Nil(), "proof has nil fields")
	assert.Equal(t, statement.Y, newProof.Y)
	assert.True(t, newProof.Proof.Verify(statement, rpA))
}
