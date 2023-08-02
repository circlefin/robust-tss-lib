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
	ra := common.GetRandomPositiveInt(pkA.N)
    Xk, err := pkA.EncryptWithRandomness(a, ra)
    assert.NoError(t, err)
	b := common.GetRandomPositiveInt(q)


	cA, pf, err := accmta.AliceInit(ec, pkA, a, ra, rpB)
	assert.NoError(t, err)
	assert.NotNil(t, pf)
	assert.NotNil(t, cA)
	assert.Equal(t, 0, Xk.Cmp(cA))
	statementA := &zkproofs.EncStatement{
		K:  cA,    // Alice's ciphertext
		N0: pkA.N, // Alice's public key
		EC: ec,    // max size of plaintext
	}
	verify := pf.Verify(statementA, rpB)
	assert.True(t, verify)

    rpVs := []*zkproofs.RingPedersenParams{rpA, rpA, nil, rpB}
    cB, err := skB.Encrypt(b)
    assert.NoError(t, err)
	beta, cAlpha, cBeta, cBetaPrm, proofs, decProofs, err := accmta.BobRespondsP(ec, pkA, skB, pf, cB, cA, rpVs, rpB)
	assert.NoError(t, err)
	assert.NotNil(t, beta)
	assert.NotNil(t, cAlpha)
	assert.NotNil(t, cBetaPrm)
	assert.NotNil(t, cBeta)
	assert.NotNil(t, cB)
	assert.NotNil(t, proofs)
	assert.NotNil(t, decProofs)
	assert.Equal(t, len(rpVs), len(proofs))

	betaPrm, err := skB.Decrypt(cBetaPrm)
	assert.NoError(t, err)
	assert.True(t, common.ModInt(q).IsAdditiveInverse(beta, betaPrm))

    for i, _ := range rpVs {
        if rpVs[i] != nil  {
            assert.NotNil(t, proofs[i])
        }
        assert.True(t, accmta.AliceVerifyP(ec, &skA.PublicKey, pkB, proofs[i], cA, cAlpha, cBetaPrm, cB, rpVs[i]))
        assert.True(t, accmta.DecProofVerify(pkB, ec, decProofs[i], cBeta, cBetaPrm, rpVs[i]))
    }
	alpha, err := accmta.AliceEndP(ec, skA, pkB, proofs[0], decProofs[0], cA, cAlpha, cBeta, cBetaPrm, cB, rpA)
	assert.NotNil(t, alpha)
	assert.NoError(t, err)

	// expect: alpha + beta = ab
	right := common.ModInt(q).Add(alpha, beta)
	left := common.ModInt(q).Mul(a, b)
	assert.Equal(t, 0, left.Cmp(right))
}

func TestDecTest(t *testing.T) {
    setUp(t)
    modQ := common.ModInt(q)
    zero := big.NewInt(0)

    betaPrm := common.GetRandomPositiveInt(q)
    beta := modQ.Sub(zero, betaPrm)
    assert.True(t, modQ.IsCongruent(zero, modQ.Add(beta, betaPrm)))

    cBeta, _, _ := pkB.EncryptAndReturnRandomness(beta)
    cBetaPrm, _, _ := pkB.EncryptAndReturnRandomness(betaPrm)
    cZero, _ := pkB.HomoAdd(cBeta, cBetaPrm) // actually should be q
    dZero, rho, _ := skB.DecryptFull(cZero)
    assert.Equal(t, 0, dZero.Cmp(q))
    assert.True(t, modQ.IsCongruent(dZero, zero))

	decStatement := &zkproofs.DecStatement{
	    Q: q,
	    Ell: zkproofs.GetEll(tss.EC()),
	    N0: pkB.N,
	    C: cZero,
	    X: zero,
	}
	decWitness := &zkproofs.DecWitness{
        Y: q,
        Rho: rho,
	}
	proof := zkproofs.NewDecProof(decWitness, decStatement, rpA)
	assert.NotNil(t, proof)
	assert.True(t, proof.Verify(decStatement, rpA))


}

func TestMTA_DL(t *testing.T) {
	setUp(t)

	a := common.GetRandomPositiveInt(q)
	ra := common.GetRandomPositiveInt(pkA.N)
    Xk, err := pkA.EncryptWithRandomness(a, ra)
    assert.NoError(t, err)
	b := common.GetRandomPositiveInt(q)

	cA, pf, err := accmta.AliceInit(ec, pkA, a, ra, rpB)
	assert.NoError(t, err)
	assert.NotNil(t, pf)
	assert.NotNil(t, cA)
	assert.Equal(t, 0, Xk.Cmp(cA))

    rpVs := []*zkproofs.RingPedersenParams{rpA, rpA, nil, rpB}
	B := crypto.ScalarBaseMult(ec, b)
	assert.NoError(t, err)
	beta, cAlpha, cBeta, cBetaPrm, proofs, decProofs, err := accmta.BobRespondsDL(ec, pkA, skB, pf, b, cA, rpVs, rpB, B)
	assert.NoError(t, err)
	assert.NotNil(t, beta)
	assert.NotNil(t, cAlpha)
	assert.NotNil(t, cBetaPrm)
	assert.NotNil(t, proofs)
	assert.Equal(t, len(rpVs), len(proofs))

    for i, _ := range rpVs {
        if rpVs[i] != nil  {
            assert.NotNil(t, proofs[i])
        }
        assert.True(t, accmta.AliceVerifyDL(ec, &skA.PublicKey, pkB, proofs[i], cA, cAlpha, cBetaPrm, B, rpVs[i]))
        assert.True(t, accmta.DecProofVerify(pkB, ec, decProofs[i], cBeta, cBetaPrm, rpVs[i]))
    }
	alpha, err := accmta.AliceEndDL(ec, skA, pkB, proofs[0], decProofs[0], cA, cAlpha, cBeta, cBetaPrm, B, rpA)
	assert.NotNil(t, alpha)
	assert.NoError(t, err)

	// expect: alpha + beta = ab
	right := common.ModInt(q).Add(alpha, beta)
	left := common.ModInt(q).Mul(a, b)
	assert.Equal(t, 0, left.Cmp(right))
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
