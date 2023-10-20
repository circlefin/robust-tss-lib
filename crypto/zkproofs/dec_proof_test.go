//  Copyright (c) 2023, Circle Internet Financial, LTD.
//  All rights reserved
//  SPDX-License-Identifier: Apache-2.0
//
package zkproofs_test

import (
	"math/big"
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

func TestDecSumProof(t *testing.T) {
	setUp(t)

	sumX := big.NewInt(20)
	one, _ := publicKey.Encrypt(big.NewInt(1))
	sumBigX, _, err := publicKey.HomoMultAndReturnRandomness(sumX, one)
	assert.NoError(t, err)
	for i := 0; i < 60; i++ {
		x := common.GetRandomPositiveInt(q)
		X, err := publicKey.Encrypt(x)
		assert.NoError(t, err)
		sumX = common.ModInt(q).Add(sumX, x)
		sumBigX, err = publicKey.HomoAdd(sumBigX, X)
		assert.NoError(t, err)
	}

	sum, rho, err := privateKey.DecryptFull(sumBigX)

	// witness
	witness := &zkproofs.DecWitness{
		Y:   sum,
		Rho: rho,
	}
	statement := &zkproofs.DecStatement{
		Q:   q,
		Ell: ell,
		N0:  publicKey.N,
		C:   sumBigX,
		X:   sumX,
	}

	// Prove that:
	// C = Encrypt(N0, x, rho)
	// y = x mod q
	proof := zkproofs.NewDecProof(witness, statement, ringPedersen)
	assert.NotNil(t, proof)
	assert.False(t, proof.Nil())
	assert.True(t, proof.Verify(statement, ringPedersen))
}

func GenerateDecProofData(t *testing.T) (*zkproofs.DecWitness, *zkproofs.DecStatement) {
	y := common.GetRandomPositiveInt(publicKey.N)
	x := new(big.Int).Mod(y, q)
	witness := &zkproofs.DecWitness{
		Y:   y,
		Rho: common.GetRandomPositiveInt(publicKey.N),
	}

	// C = Encrypt(N0, k, rho)
	C, err := publicKey.EncryptWithRandomness(y, witness.Rho)
	assert.NoError(t, err, "encrypt C not error")
	statement := &zkproofs.DecStatement{
		Q:   q,
		Ell: ell,
		N0:  publicKey.N,
		C:   C,
		X:   x,
	}
	return witness, statement
}

func TestDecProofBytes(t *testing.T) {
	setUp(t)
	witness, statement := GenerateDecProofData(t)

	// Prove that:
	// C = Encrypt(N0, x, rho)
	// y = x mod q
	proof := zkproofs.NewDecProof(witness, statement, ringPedersen)
	assert.NotNil(t, proof)
	assert.False(t, proof.Nil())
	assert.True(t, proof.Verify(statement, ringPedersen))

	proofBytes := proof.Bytes()
	var proofInBytes [][]byte = proofBytes[:]
	np, err := new(zkproofs.DecProof).ProofFromBytes(ec, proofInBytes)
	newProof := np.(*zkproofs.DecProof)
	assert.NoError(t, err)
	assert.NotNil(t, newProof)
	assert.False(t, newProof.Nil())
	assert.True(t, newProof.Verify(statement, ringPedersen))
}

func TestDecProofArrayBytes(t *testing.T) {
	setUp(t)
	witness, statement := GenerateDecProofData(t)
	proof := zkproofs.NewDecProof(witness, statement, ringPedersen)

	array := []*zkproofs.DecProof{proof, proof, nil, proof}
	bzs := zkproofs.ProofArrayToBytes(array)
	out, err := zkproofs.ProofArrayFromBytes[*zkproofs.DecProof](ec, bzs)
	assert.NoError(t, err)
	assert.Equal(t, len(array), len(out))
	assert.NotNil(t, out[0])
	assert.NotNil(t, out[1])
	assert.NotNil(t, out[3])
	assert.True(t, out[0].Verify(statement, ringPedersen))
	assert.True(t, out[1].Verify(statement, ringPedersen))
	assert.Nil(t, out[2])
	assert.True(t, out[3].Verify(statement, ringPedersen))
}
