package zkproofs_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto/zkproofs"
)

func TestDecProof(t *testing.T) {
	setUp(t)

	// witness
	witness := &zkproofs.DecWitness{
		Y:   common.GetRandomPositiveInt(q),
		Rho: common.GetRandomPositiveInt(q),
	}

	// C = Encrypt(N0, k, rho)
	C, err := publicKey.EncryptWithRandomness(witness.Y, witness.Rho)
	assert.NoError(t, err, "encrypt C not error")
	statement := &zkproofs.DecStatement{
		Q:   q,
		Ell: ell,
		N0:  publicKey.N,
		C:   C,
		X:   witness.Y,
	}

	// Prove that:
	// C = Encrypt(N0, x, rho)
	// y = x mod q
	proof := zkproofs.NewDecProof(witness, statement, ringPedersen)
	assert.NotNil(t, proof)
	assert.False(t, proof.Nil())
	assert.True(t, proof.Verify(statement, ringPedersen))
}

func TestDecProofBytes(t *testing.T) {
	setUp(t)

	// witness
	witness := &zkproofs.DecWitness{
		Y:   common.GetRandomPositiveInt(q),
		Rho: common.GetRandomPositiveInt(q),
	}

	// C = Encrypt(N0, k, rho)
	C, err := publicKey.EncryptWithRandomness(witness.Y, witness.Rho)
	assert.NoError(t, err, "encrypt C not error")
	statement := &zkproofs.DecStatement{
		Q:   q,
		Ell: ell,
		N0:  publicKey.N,
		C:   C,
		X:   witness.Y,
	}

	// Prove that:
	// C = Encrypt(N0, x, rho)
	// y = x mod q
	proof := zkproofs.NewDecProof(witness, statement, ringPedersen)
	assert.NotNil(t, proof)
	assert.False(t, proof.Nil())
	assert.True(t, proof.Verify(statement, ringPedersen))

	proofBytes := proof.Bytes()
	var proofInBytes [][]byte = proofBytes[:]
	newProof, err := zkproofs.DecProofFromBytes(proofInBytes)
	assert.NoError(t, err)
	assert.NotNil(t, newProof)
	assert.False(t, newProof.Nil())
	assert.True(t, newProof.Verify(statement, ringPedersen))
}
