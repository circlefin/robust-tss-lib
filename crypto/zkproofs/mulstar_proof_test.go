// Copyright (c) 2023, Circle Internet Financial, LTD.
// All rights reserved
// SPDX-License-Identifier: Apache-2.0
package zkproofs_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/crypto/zkproofs"
	"github.com/bnb-chain/tss-lib/tss"
)

func TestMulStarProof(t *testing.T) {
	setUp(t)
	ec := tss.EC()

	x := common.GetRandomPositiveInt(q)
	X := crypto.ScalarBaseMult(ec, x)

	y := common.GetRandomPositiveInt(q)
	C, err := publicKey.Encrypt(y)
	assert.NoError(t, err, "encrypt C not error")

	D, rho, err := publicKey.HomoMultAndReturnRandomness(x, C)
	assert.NoError(t, err, "encrypt D not error")

	witness := &zkproofs.MulStarWitness{
		X:   x,
		Rho: rho,
	}
	statement := &zkproofs.MulStarStatement{
		Ell: ell,
		N0:  publicKey.N,
		C:   C,
		D:   D,
		X:   X,
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
	x := common.GetRandomPositiveInt(q)
	X := crypto.ScalarBaseMult(ec, x)

	y := common.GetRandomPositiveInt(q)
	C, err := publicKey.Encrypt(y)
	assert.NoError(t, err, "encrypt C not error")

	D, rho, err := publicKey.HomoMultAndReturnRandomness(x, C)
	assert.NoError(t, err, "encrypt D not error")

	witness := &zkproofs.MulStarWitness{
		X:   x,
		Rho: rho,
	}
	statement := &zkproofs.MulStarStatement{
		Ell: ell,
		N0:  publicKey.N,
		C:   C,
		D:   D,
		X:   X,
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
	np, err := new(zkproofs.MulStarProof).ProofFromBytes(ec, proofInBytes)
	newProof := np.(*zkproofs.MulStarProof)
	assert.NoError(t, err)
	assert.NotNil(t, newProof)
	assert.False(t, newProof.Nil())
	assert.True(t, newProof.Verify(statement, ringPedersen))
}
