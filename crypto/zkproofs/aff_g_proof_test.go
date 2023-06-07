package zkproofs_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/crypto/zkproofs"
)

func TestAffGProof(t *testing.T) {
	setUp(t)
	N := publicKey.N
	N2 := new(big.Int).Mul(N, N)


    // Specifically,the Prover has secret input (x, y, rho, rhox, rhoy) such that
	c := common.GetRandomPositiveInt(q)
	x := common.GetRandomPositiveInt(q)
	y :=common.GetRandomPositiveInt(q)
	rho := common.GetRandomPositiveInt(q)
	rhoy := common.GetRandomPositiveInt(q)
    witness := &zkproofs.AffGWitness {
        X: x,
        Y: y,
        Rho: rho,
        Rhoy: rhoy,
    }

	// X = g^x
    X := crypto.ScalarBaseMult(ec, witness.X)
    //  Y = (1+N1)^y * rhoy^N1 mod N1^2
    Y, _ := publicKey.EncryptWithRandomness(y, rhoy)
    //  D  = C^x * (1+N0)^y * rho^N0 mod N0^2
    C, _ := publicKey.Encrypt(c)
    Dprime, _ := publicKey.EncryptWithRandomness(y, rho)
    D := zkproofs.ATimesBToTheCModN(Dprime, C, x, N2)
    statement := &zkproofs.AffGStatement{
        C: C,
        D: D,
        X: X,
        Y: Y,
        N0: publicKey.N,
        N1: publicKey.N,
        Ell: ell,
        EllPrime: ell,
    }


	proof, err := zkproofs.NewAffGProof(witness, statement, ringPedersen)
	assert.NoError(t, err, "could not create NewAffGProof")
	assert.NotNil(t, proof, "NewAffGProof nil")
	assert.False(t, proof.Nil(), "proof has nil fields")
	assert.True(t,proof.Verify(statement, ringPedersen), "proof does not verify")
}

func TestAffGProofBytes(t *testing.T) {
	setUp(t)
	N := publicKey.N
	N2 := new(big.Int).Mul(N, N)


    // Specifically,the Prover has secret input (x, y, rho, rhox, rhoy) such that
	c := common.GetRandomPositiveInt(q)
	x := common.GetRandomPositiveInt(q)
	y :=common.GetRandomPositiveInt(q)
	rho := common.GetRandomPositiveInt(q)
	rhoy := common.GetRandomPositiveInt(q)
    witness := &zkproofs.AffGWitness {
        X: x,
        Y: y,
        Rho: rho,
        Rhoy: rhoy,
    }

	// X = g^x
    X := crypto.ScalarBaseMult(ec, witness.X)
    //  Y = (1+N1)^y * rhoy^N1 mod N1^2
    Y, _ := publicKey.EncryptWithRandomness(y, rhoy)
    //  D  = C^x * (1+N0)^y * rho^N0 mod N0^2
    C, _ := publicKey.Encrypt(c)
    Dprime, _ := publicKey.EncryptWithRandomness(y, rho)
    D := zkproofs.ATimesBToTheCModN(Dprime, C, x, N2)
    statement := &zkproofs.AffGStatement{
        C: C,
        D: D,
        X: X,
        Y: Y,
        N0: publicKey.N,
        N1: publicKey.N,
        Ell: ell,
        EllPrime: ell,
    }

	proof, err := zkproofs.NewAffGProof(witness, statement, ringPedersen)
	assert.NoError(t, err, "could not create NewAffGProof")
	assert.NotNil(t, proof, "NewAffGProof nil")
	assert.False(t, proof.Nil(), "proof has nil fields")
	assert.True(t,proof.Verify(statement, ringPedersen), "proof does not verify")

	proofBytes := proof.Bytes()
	var proofInBytes [][]byte = proofBytes[:]
	newProof, err := zkproofs.AffGProofFromBytes(ec, proofInBytes)
	assert.NoError(t, err, "could not create NewAffGProof")
	assert.NotNil(t, newProof, "NewAffGProof nil")
	assert.False(t, newProof.Nil(), "proof has nil fields")
	assert.True(t,newProof.Verify(statement, ringPedersen), "proof does not verify")
}
