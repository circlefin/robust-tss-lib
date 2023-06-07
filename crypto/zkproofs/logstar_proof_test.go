package zkproofs_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/crypto/zkproofs"
)

func TestLogStarProof(t *testing.T) {
	setUp(t)

    // witness
    witness := &zkproofs.LogStarWitness{
        X: common.GetRandomPositiveInt(q),
        Rho: common.GetRandomPositiveInt(publicKey.N),
    }

	// X = g^x
    X := crypto.ScalarBaseMult(ec, witness.X)

	// C = Encrypt(N0, x, rho)
	C, err := publicKey.EncryptWithRandomness(witness.X, witness.Rho)
	assert.NoError(t, err, "encrypt C not error")

	statement := &zkproofs.LogStarStatement{
	    Ell: ell,
	    N0: publicKey.N,
	    C: C,
	    X: X,
	}

	// Prove that:
	// X = g^x
	// C = Encrypt(N0, x, rho)
	proof := zkproofs.NewLogStarProof(witness, statement, ringPedersen)
	assert.NoError(t, err)
	assert.NotNil(t, proof)
	assert.True(t, proof.Verify(statement, ringPedersen), "proof failed to verify")
}

func TestLogStarProofBytes(t *testing.T) {
	setUp(t)

    // witness
    witness := &zkproofs.LogStarWitness{
        X: common.GetRandomPositiveInt(q),
        Rho: common.GetRandomPositiveInt(publicKey.N),
    }

	// X = g^x
    X := crypto.ScalarBaseMult(ec, witness.X)

	// C = Encrypt(N0, x, rho)
	C, err := publicKey.EncryptWithRandomness(witness.X, witness.Rho)
	assert.NoError(t, err, "encrypt C not error")

	statement := &zkproofs.LogStarStatement{
	    Ell: ell,
	    N0: publicKey.N,
	    C: C,
	    X: X,
	}

	// Prove that:
	// X = g^x
	// C = Encrypt(N0, x, rho)
	proof := zkproofs.NewLogStarProof(witness, statement, ringPedersen)
	assert.NoError(t, err)
	assert.NotNil(t, proof)
	assert.True(t, proof.Verify(statement, ringPedersen), "proof failed to verify")

	proofBytes := proof.Bytes()
	var proofInBytes [][]byte = proofBytes[:]
	newProof, err := zkproofs.LogStarProofFromBytes(ec, proofInBytes)
	assert.NoError(t, err)
	assert.NotNil(t, newProof)
	assert.False(t, newProof.Nil())
	assert.True(t,newProof.Verify(statement, ringPedersen))

}
