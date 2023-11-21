// Copyright (c) 2023, Circle Internet Financial, LTD. All rights reserved.
//
//  SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package zkproofs_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto/zkproofs"
)

func TestEncProof(t *testing.T) {
	setUp(t)

	// K = Encrypt(N0, k, rho)
	k := common.GetRandomPositiveInt(q)
	K, rho, err := publicKey.EncryptAndReturnRandomness(k)
	assert.NoError(t, err, "encrypt K not error")
	// witness
	witness := &zkproofs.EncWitness{
		K:   k,
		Rho: rho,
	}

	statement := &zkproofs.EncStatement{
		EC: ec,
		N0: publicKey.N,
		K:  K,
	}

	// Prove that:
	// C = Encrypt(N0, x, rho)
	// k \in +- 2^{ell+epsilon}
	proof, err := zkproofs.NewEncProof(witness, statement, ringPedersen)
	assert.NoError(t, err)
	assert.True(t, proof.Verify(statement, ringPedersen), "proof failed to verify")
}

func TestEncProofBytes(t *testing.T) {
	setUp(t)

	// K = Encrypt(N0, k, rho)
	k := common.GetRandomPositiveInt(q)
	K, rho, err := publicKey.EncryptAndReturnRandomness(k)
	assert.NoError(t, err, "encrypt K not error")
	// witness
	witness := &zkproofs.EncWitness{
		K:   k,
		Rho: rho,
	}

	statement := &zkproofs.EncStatement{
		EC: ec,
		N0: publicKey.N,
		K:  K,
	}

	// Prove that:
	// C = Encrypt(N0, x, rho)
	// k \in +- 2^{ell+epsilon}
	proof, err := zkproofs.NewEncProof(witness, statement, ringPedersen)
	assert.NoError(t, err)
	assert.NotNil(t, proof)
	assert.True(t, proof.Verify(statement, ringPedersen), "proof failed to verify")

	proofBytes := proof.Bytes()
	var proofInBytes [][]byte = proofBytes[:]
	np, err := new(zkproofs.EncProof).ProofFromBytes(ec, proofInBytes)
	newProof := np.(*zkproofs.EncProof)
	assert.NoError(t, err)
	assert.NotNil(t, newProof)
	assert.False(t, newProof.Nil())
	assert.True(t, newProof.Verify(statement, ringPedersen))
}
