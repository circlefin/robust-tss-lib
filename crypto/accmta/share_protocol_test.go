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
	pkA, pkB  *paillier.PublicKey
	rpA, rpB *zkproofs.RingPedersenParams
	ec elliptic.Curve
	q *big.Int
	ell *big.Int
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
    sk =fixture.PaillierSK
    pk = &paillier.PublicKey{N: sk.N}
	return
}

func TestMT_P(t *testing.T) {
    setUp(t)

	a := common.GetRandomPositiveInt(q)
	b := common.GetRandomPositiveInt(q)

	cA, pf, err := accmta.AliceInit(ec, pkA, a, rpB)
	assert.NoError(t, err)
	assert.NotNil(t, pf)
	assert.NotNil(t, cA)
	   statementA := &zkproofs.EncStatement{
            K: cA, // Alice's ciphertext
            N0: pkA.N, // Alice's public key
            EC: ec, // max size of plaintext
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

func TestMT_DL(t *testing.T) {
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
