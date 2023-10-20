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

func TestMulProof(t *testing.T) {
	setUp(t)
	N := publicKey.N
	N2 := new(big.Int).Mul(N, N)

	// X = (1+N)^x * rhox^N mod N2
	x := common.GetRandomPositiveInt(q)
	X, err := publicKey.Encrypt(x)
	assert.NoError(t, err, "encrypt x not error")
	_, rhox, err := privateKey.DecryptFull(X)
	assert.NoError(t, err, "decrypt full X not error")

	// Y = (1+N)^2 rhoy^N mod N2
	y := common.GetRandomPositiveInt(q)
	Y, err := publicKey.Encrypt(y)
	assert.NoError(t, err, "encrypt y not error")

	// C = Y^x rho^N  mod N2
	rho := common.GetRandomPositiveInt(N)
	C := zkproofs.PseudoPaillierEncrypt(Y, x, rho, N, N2)

	witness := &zkproofs.MulWitness{
		X:    x,
		Rho:  rho,
		Rhox: rhox,
	}
	statement := &zkproofs.MulStatement{
		N: publicKey.N,
		X: X,
		Y: Y,
		C: C,
	}

	// Prove that:
	// X =(1 + N)^x rhox^N mod N^2
	// C = Y^x rho^N mod N^2
	proof := zkproofs.NewMulProof(witness, statement)
	assert.NoError(t, err)
	assert.NotNil(t, proof)
	assert.True(t, proof.Verify(statement), "proof failed to verify")
}

func TestMulProofBytes(t *testing.T) {
	setUp(t)
	N := publicKey.N
	N2 := new(big.Int).Mul(N, N)

	// X = (1+N)^x * rhox^N mod N2
	x := common.GetRandomPositiveInt(q)
	X, err := publicKey.Encrypt(x)
	assert.NoError(t, err, "encrypt x not error")
	_, rhox, err := privateKey.DecryptFull(X)
	assert.NoError(t, err, "decrypt full X not error")

	// Y = (1+N)^2 rhoy^N mod N2
	y := common.GetRandomPositiveInt(q)
	Y, err := publicKey.Encrypt(y)
	assert.NoError(t, err, "encrypt y not error")

	// C = Y^x rho^N  mod N2
	rho := common.GetRandomPositiveInt(N)
	C := zkproofs.PseudoPaillierEncrypt(Y, x, rho, N, N2)

	witness := &zkproofs.MulWitness{
		X:    x,
		Rho:  rho,
		Rhox: rhox,
	}
	statement := &zkproofs.MulStatement{
		N: publicKey.N,
		X: X,
		Y: Y,
		C: C,
	}

	// Prove that:
	// X =(1 + N)^x rhox^N mod N^2
	// C = Y^x rho^N mod N^2
	proof := zkproofs.NewMulProof(witness, statement)
	assert.NoError(t, err)
	assert.NotNil(t, proof)
	assert.True(t, proof.Verify(statement), "proof failed to verify")

	proofBytes := proof.Bytes()
	var proofInBytes [][]byte = proofBytes[:]
	newProof, err := zkproofs.MulProofFromBytes(proofInBytes)
	assert.NoError(t, err)
	assert.NotNil(t, newProof)
	assert.False(t, newProof.Nil())
	assert.True(t, newProof.Verify(statement))
}
