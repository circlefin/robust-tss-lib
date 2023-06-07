package zkproofs_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/tss"
	"github.com/bnb-chain/tss-lib/crypto/zkproofs"
)

func TestMulStarProof(t *testing.T) {
	setUp(t)
	ec := tss.EC()
	N0 := publicKey.N
	N02 := new(big.Int).Mul(N0, N0)

    // witness
    x := common.GetRandomPositiveInt(q)
    y := common.GetRandomPositiveInt(q)
    rho :=  common.GetRandomPositiveInt(publicKey.N)
    witness := &zkproofs.MulStarWitness{
        X: x,
        Rho: rho,
    }

	// X = g^x
    X := crypto.ScalarBaseMult(ec, x)

	// C = Encrypt(N0, y)
	C, err := publicKey.Encrypt(y)
	assert.NoError(t, err, "encrypt C not error")

	// D = Encrypt(N0, xy) = C^x rho^N0 mod N02
    D := zkproofs.PseudoPaillierEncrypt(C, x, rho, N0, N02)
    statement := &zkproofs.MulStarStatement{
        Ell: ell,
        N0: publicKey.N,
        C: C,
        D: D,
        X: X,
    }

	// Prove that:
	// X = g^x
	// D = C^x rho^N2 mod N02
	proof := zkproofs.NewMulStarProof(witness, statement, ringPedersen)
	assert.NoError(t, err)
	assert.NotNil(t, proof)
	assert.True(t, proof.Verify(statement, ringPedersen), "proof failed to verify")
}

func TestMulStarProofBytes(t *testing.T) {
	setUp(t)
	ec := tss.EC()
	N0 := publicKey.N
	N02 := new(big.Int).Mul(N0, N0)

    // witness
    x := common.GetRandomPositiveInt(q)
    y := common.GetRandomPositiveInt(q)
    rho :=  common.GetRandomPositiveInt(publicKey.N)
    witness := &zkproofs.MulStarWitness{
        X: x,
        Rho: rho,
    }

	// X = g^x
    X := crypto.ScalarBaseMult(ec, x)

	// C = Encrypt(N0, y)
	C, err := publicKey.Encrypt(y)
	assert.NoError(t, err, "encrypt C not error")

	// D = Encrypt(N0, xy) = C^x rho^N0 mod N02
    D := zkproofs.PseudoPaillierEncrypt(C, x, rho, N0, N02)
    statement := &zkproofs.MulStarStatement{
        Ell: ell,
        N0: publicKey.N,
        C: C,
        D: D,
        X: X,
    }

	// Prove that:
	// X = g^x
	// D = C^x rho^N2 mod N02
	proof := zkproofs.NewMulStarProof(witness, statement, ringPedersen)
	assert.NoError(t, err)
	assert.NotNil(t, proof)
	assert.True(t, proof.Verify(statement, ringPedersen), "proof failed to verify")

	proofBytes := proof.Bytes()
	var proofInBytes [][]byte = proofBytes[:]
	newProof, err := zkproofs.MulStarProofFromBytes(ec, proofInBytes)
	assert.NoError(t, err)
	assert.NotNil(t, newProof)
	assert.False(t, newProof.Nil())
	assert.True(t,newProof.Verify(statement, ringPedersen))
}
