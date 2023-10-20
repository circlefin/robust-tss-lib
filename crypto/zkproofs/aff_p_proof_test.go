// Copyright (c) 2023, Circle Internet Financial, LTD.
// All rights reserved
// SPDX-License-Identifier: Apache-2.0
package zkproofs_test

import (
	"math/big"
	"testing"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto/zkproofs"
	"github.com/stretchr/testify/assert"
)

func GenerateAffPData(t *testing.T) (*zkproofs.AffPWitness, *zkproofs.AffPStatement) {
	_, pk0, _, err := GetSavedKeys(0)
	assert.NoError(t, err)
	_, pk1, _, err := GetSavedKeys(1)
	assert.NoError(t, err)

	N02 := new(big.Int).Mul(pk0.N, pk0.N)

	// Specifically,the Prover has secret input (x, y, rho, rhox, rhoy) such that
	x := common.GetRandomPositiveInt(q)
	y := common.GetRandomPositiveInt(q)
	rho := common.GetRandomPositiveInt(q) //common.GetRandomPositiveInt(big.NewInt(1))
	rhox := common.GetRandomPositiveInt(pk1.N)
	rhoy := common.GetRandomPositiveInt(pk1.N)
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
	Dprime, err := pk0.EncryptWithRandomness(y, rho)
	assert.NoError(t, err)
	D := zkproofs.ATimesBToTheCModN(Dprime, C, x, N02)
	//  X = (1+N1)^x * rhox^N1 mod N1^2
	X, _ := pk1.EncryptWithRandomness(x, rhox)
	//  Y = (1+N1)^y * rhoy^N1 mod N1^2
	Y, _ := pk1.EncryptWithRandomness(y, rhoy)
	statement := &zkproofs.AffPStatement{
		C:        C,
		D:        D,
		X:        X,
		Y:        Y,
		N0:       pk0.N,
		N1:       pk1.N,
		Ell:      ell,
		EllPrime: ell,
		EC:       ec,
	}
	return witness, statement
}

func TestAffPProof(t *testing.T) {
	setUp(t)
	witness, statement := GenerateAffPData(t)

	proof, err := zkproofs.NewAffPProof(witness, statement, ringPedersen)
	assert.NoError(t, err)
	assert.NotNil(t, proof)
	assert.False(t, proof.IsNil())
	assert.True(t, proof.Verify(statement, ringPedersen), "proof failed to verify")
}

func TestAffPProofBytes(t *testing.T) {
	setUp(t)
	witness, statement := GenerateAffPData(t)

	proof, err := zkproofs.NewAffPProof(witness, statement, ringPedersen)
	assert.NoError(t, err)
	assert.NotNil(t, proof)
	assert.False(t, proof.IsNil())
	assert.True(t, proof.Verify(statement, ringPedersen), "proof failed to verify")

	proofBytes := proof.Bytes()
	var proofInBytes [][]byte = proofBytes[:]
	np, err := new(zkproofs.AffPProof).ProofFromBytes(ec, proofInBytes)
	newProof := np.(*zkproofs.AffPProof)
	assert.NoError(t, err, "could not create NewAffPProof")
	assert.NotNil(t, newProof, "NewAffPProof nil")
	assert.False(t, newProof.IsNil(), "proof has nil fields")
	assert.True(t, newProof.Verify(statement, ringPedersen), "proof does not verify")
	assert.Equal(t, 0, proof.A.Cmp(newProof.A))
	assert.Equal(t, 0, proof.Bx.Cmp(newProof.Bx))
	assert.Equal(t, 0, proof.By.Cmp(newProof.By))
	assert.Equal(t, 0, proof.E.Cmp(newProof.E))
	assert.Equal(t, 0, proof.S.Cmp(newProof.S))
	assert.Equal(t, 0, proof.F.Cmp(newProof.F))
	assert.Equal(t, 0, proof.T.Cmp(newProof.T))
	assert.Equal(t, 0, proof.Z1.Cmp(newProof.Z1))
	assert.Equal(t, 0, proof.Z2.Cmp(newProof.Z2))
	assert.Equal(t, 0, proof.Z3.Cmp(newProof.Z3))
	assert.Equal(t, 0, proof.Z4.Cmp(newProof.Z4))
	assert.Equal(t, 0, proof.W.Cmp(newProof.W))
	assert.Equal(t, 0, proof.Wx.Cmp(newProof.Wx))
	assert.Equal(t, 0, proof.Wy.Cmp(newProof.Wy))
}

func TestAffPProofArrayBytes(t *testing.T) {
	setUp(t)
	witness, statement := GenerateAffPData(t)

	proof, err := zkproofs.NewAffPProof(witness, statement, ringPedersen)
	array := []*zkproofs.AffPProof{proof, proof, nil, proof}
	bzs := zkproofs.ProofArrayToBytes(array)
	out, err := zkproofs.ProofArrayFromBytes[*zkproofs.AffPProof](ec, bzs)
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
