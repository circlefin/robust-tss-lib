package zkproofs_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/crypto/zkproofs"
)

func GenerateAffGData(t *testing.T) (*zkproofs.AffGWitness, *zkproofs.AffGStatement) {
	N := publicKey.N
	N2 := new(big.Int).Mul(N, N)

	// Specifically,the Prover has secret input (x, y, rho, rhox, rhoy) such that
	c := common.GetRandomPositiveInt(q)
	x := common.GetRandomPositiveInt(q)
	y := common.GetRandomPositiveInt(q)
	rho := common.GetRandomPositiveInt(q)
	rhoy := common.GetRandomPositiveInt(q)
	witness := &zkproofs.AffGWitness{
		X:    x,
		Y:    y,
		Rho:  rho,
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
		C:        C,
		D:        D,
		X:        X,
		Y:        Y,
		N0:       publicKey.N,
		N1:       publicKey.N,
		Ell:      ell,
		EllPrime: ell,
	}
	return witness, statement
}

func TestAffGProof(t *testing.T) {
	setUp(t)
	witness, statement := GenerateAffGData(t)
	proof, err := zkproofs.NewAffGProof(witness, statement, ringPedersen)
	assert.NoError(t, err, "could not create NewAffGProof")
	assert.NotNil(t, proof, "NewAffGProof nil")
	assert.False(t, proof.IsNil(), "proof has nil fields")
	assert.True(t, proof.Verify(statement, ringPedersen), "proof does not verify")
}

func TestAffGProofBytes(t *testing.T) {
	setUp(t)
	witness, statement := GenerateAffGData(t)
	proof, err := zkproofs.NewAffGProof(witness, statement, ringPedersen)
	assert.NoError(t, err, "could not create NewAffGProof")
	assert.NotNil(t, proof, "NewAffGProof nil")
	assert.False(t, proof.IsNil(), "proof has nil fields")
	assert.True(t, proof.Verify(statement, ringPedersen), "proof does not verify")

	proofBytes := proof.Bytes()
	var proofInBytes [][]byte = proofBytes[:]
	np, err := new(zkproofs.AffGProof).ProofFromBytes(ec, proofInBytes)
	newProof := np.(*zkproofs.AffGProof)
	assert.NoError(t, err, "could not create NewAffGProof")
	assert.NotNil(t, newProof, "NewAffGProof nil")
	assert.False(t, newProof.IsNil(), "proof has nil fields")
	assert.True(t, newProof.Verify(statement, ringPedersen), "proof does not verify")
}

func TestAffGProofArrayBytes(t *testing.T) {
	setUp(t)
	witness, statement := GenerateAffGData(t)

	proof, err := zkproofs.NewAffGProof(witness, statement, ringPedersen)
	array := []*zkproofs.AffGProof{proof, proof, nil, proof}
	bzs := zkproofs.ProofArrayToBytes(array)
	out, err := zkproofs.ProofArrayFromBytes[*zkproofs.AffGProof](ec, bzs)
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
