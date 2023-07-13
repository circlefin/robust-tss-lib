// Copyright 2023 Circle
//

package accsigning

import (
	//	"math/big"
    "sync"
	"testing"

	//	"github.com/ipfs/go-log"
	"github.com/stretchr/testify/assert"

	//	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto/accmta"
	"github.com/bnb-chain/tss-lib/crypto/paillier"
	"github.com/bnb-chain/tss-lib/crypto/zkproofs"
	//	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	//	"github.com/bnb-chain/tss-lib/test"
	"github.com/bnb-chain/tss-lib/tss"
)

func TestRound1(t *testing.T) {
	params, parties, outCh := SetupParties(t)
	rounds := RunRound1(t, params, parties, outCh)

	wg := sync.WaitGroup{}
	for i, sender := range parties {
		for j, receiver := range parties {
			if i == j {
				continue
			}
			wg.Add(1)
			go func(i, j int, sender, receiver *LocalParty) {
				defer wg.Done()
				msg1 := rounds[j].temp.signRound1Message1s[i].Content().(*SignRound1Message1)
				msg2 := rounds[j].temp.signRound1Message2s[i].Content().(*SignRound1Message2)
				ValidateSignRound1Messages(t, rounds[j], msg1, msg2, sender, receiver)
				return
			}(i, j, sender, receiver)
		}
	}
	wg.Wait()
}

func TestRound2(t *testing.T) {
	params, parties, outCh := SetupParties(t)
	round1s := RunRound1(t, params, parties, outCh)
	round2s := RunRound2(t, params, parties, round1s, outCh)

	wg := sync.WaitGroup{}
	for verifier, _ := range parties {
		for sender, _ := range parties {
			if sender == verifier {
				continue
			}
			wg.Add(1)
			go func(verifier, sender int) {
				defer wg.Done()
				msg := round2s[verifier].temp.signRound2Messages[sender].Content().(*SignRound2Message)
				ValidateSignRound2Message(t, round2s[verifier], sender, verifier, msg)
				return
			}(verifier, sender)
		}
	}
	wg.Wait()
}

func ValidateSignRound2Message(t *testing.T, round *round2, sender, verifier int, msg *SignRound2Message) {
	assert.NotNil(t, msg)
	recipient := msg.UnmarshalRecipient()
	cAlpha := msg.UnmarshalCAlpha()
	cBetaPrm := msg.UnmarshalCBetaPrm()
	cB := msg.UnmarshalCB()
	cMu := msg.UnmarshalCMu()
	cNuPrm := msg.UnmarshalCNuPrm()
	proofPs, err := msg.UnmarshalProofP()
	assert.NoError(t, err)
	proofDLs, err := msg.UnmarshalProofDL(tss.EC())
	assert.NoError(t, err)

	assert.True(t, recipient > -1)
	assert.NotNil(t, cAlpha)
	assert.NotNil(t, cBetaPrm)
	assert.NotNil(t, cB)
	assert.NotNil(t, cMu)
	assert.NotNil(t, cNuPrm)
	assert.NotNil(t, proofPs)
	assert.True(t, len(proofPs) > verifier)
	assert.NotNil(t, proofDLs)
	assert.True(t, len(proofDLs) > verifier)

	// the verifier is receiver
	// Alice is the recipient
	// Bob is the sender
	rpV := round.key.GetRingPedersen(verifier)
//	r1msg := round.temp.signRound1Message1s[recipient].Content().(*SignRound1Message1)
	cA := round.temp.cA[recipient]
	statementP := &zkproofs.AffPStatement{
		C:        cA,                                       // Alice's ciphertext
		D:        cAlpha,                                   // affine transform of Alice's ciphertext: cA(*)b + betaPrm
		X:        cB,                                       // encryption of b using Bob's public key
		Y:        cBetaPrm,                                 // encryption of betaPrm
		N0:       round.key.PaillierPKs[recipient].N,       // Alice's public key
		N1:       round.key.PaillierPKs[sender].N,          // Bob's public key
		Ell:      zkproofs.GetEll(tss.EC()),               // max size of plaintext
		EllPrime: zkproofs.GetEll(tss.EC()),               // max size of plaintext
		EC:       tss.EC(),                                // elliptic curve
	}
	assert.NotNil(t, statementP.C)
	assert.True(t, proofPs[verifier].Verify(statementP, rpV))

	statementDL := &zkproofs.AffGStatement{
		C:        cA,                                       // Alice's ciphertext
		D:        cMu,                                      // affine transform of Alice's ciphertext: cA(*)b + betaPrm
		X:        round.temp.bigWs[sender],                 // Bob's bigW
		Y:        cNuPrm,                                   // encryption of nuPrm
		N0:       round.key.PaillierPKs[recipient].N,       // Alice's public key
		N1:       round.key.PaillierPKs[sender].N,          // Bob's public key
		Ell:      zkproofs.GetEll(tss.EC()),                // max size of plaintext
		EllPrime: zkproofs.GetEll(tss.EC()),                // max size of plaintext
	}
	assert.NotNil(t, statementDL.C)
//	assert.True(t, proofDLs[verifier].Verify(statementDL, rpV))

}

func ValidateSignRound1Messages(t *testing.T, round *round1, msg1 *SignRound1Message1, msg2 *SignRound1Message2, sender, receiver *LocalParty) {
	ValidateRound1RangeProofAlice(t, msg1, msg2, &sender.keys.PaillierSK.PublicKey, receiver.keys.RingPedersen())
	ValidateRound1ProofXK(t, msg1, msg2, &sender.keys.PaillierSK.PublicKey, receiver.keys.RingPedersen())
	ValidateRound1ProofXGamma(t, msg1, msg2, &sender.keys.PaillierSK.PublicKey, receiver.keys.RingPedersen())
	ValidateRound1ProofXKw(t, round, msg1, msg2, &sender.keys.PaillierSK.PublicKey, receiver.keys.RingPedersen(), sender)
	ValidateRound1ProofXKGamma(t, msg2, &sender.keys.PaillierSK.PublicKey)
}

func ValidateRound1RangeProofAlice(t *testing.T, msg1 *SignRound1Message1, msg2 *SignRound1Message2, pkSender *paillier.PublicKey, rpReceiver *zkproofs.RingPedersenParams) {
	cA := msg2.UnmarshalCA()
	proof, err := msg1.UnmarshalRangeProofAlice()
	assert.NoError(t, err)
	valid := accmta.BobVerify(
		tss.EC(),
		pkSender,
		proof,
		cA,
		rpReceiver,
	)
	assert.True(t, valid)
}

func ValidateRound1ProofXK(t *testing.T, msg1 *SignRound1Message1, msg2 *SignRound1Message2, pkSender *paillier.PublicKey, rpReceiver *zkproofs.RingPedersenParams) {
	cA := msg2.UnmarshalCA()
	proof, err := msg1.UnmarshalProofXK()
	assert.NoError(t, err)
	statementXk := &zkproofs.EncStatement{
		EC: tss.EC(),
		N0: pkSender.N,
		K:  cA,
	}
	valid := proof.Verify(statementXk, rpReceiver)
	assert.True(t, valid)
}

func ValidateRound1ProofXGamma(t *testing.T, msg1 *SignRound1Message1, msg2 *SignRound1Message2, pkSender *paillier.PublicKey, rpReceiver *zkproofs.RingPedersenParams) {
	Xgamma := msg2.UnmarshalXGamma()
	proof, err := msg1.UnmarshalProofXGamma()
	assert.NoError(t, err)
	statementXGamma := &zkproofs.EncStatement{
		EC: tss.EC(),
		N0: pkSender.N,
		K:  Xgamma,
	}
	valid := proof.Verify(statementXGamma, rpReceiver)
	assert.True(t, valid)
}

func ValidateRound1ProofXKw(t *testing.T, round *round1, msg1 *SignRound1Message1, msg2 *SignRound1Message2, pkSender *paillier.PublicKey, rpReceiver *zkproofs.RingPedersenParams, sender *LocalParty) {
	cA := msg2.UnmarshalCA()
	Xkw := msg2.UnmarshalXKw()
	bigW := round.temp.bigWs[sender.PartyID().Index]
	proof, err := msg1.UnmarshalProofXKw(tss.EC())
	assert.NoError(t, err)
	statementXkw := &zkproofs.MulStarStatement{
		Ell: zkproofs.GetEll(round.Params().EC()),
		N0:  pkSender.N,
		C:   cA,
		D:   Xkw,
		X:   bigW,
	}
	valid := proof.Verify(statementXkw, rpReceiver)
	assert.True(t, valid)
}

func ValidateRound1ProofXKGamma(t *testing.T, msg2 *SignRound1Message2, pkSender *paillier.PublicKey) {
	Xgamma := msg2.UnmarshalXGamma()
	cA := msg2.UnmarshalCA()
	Xkgamma := msg2.UnmarshalXKGamma()
	proof, err := msg2.UnmarshalProofXKgamma()
	assert.NoError(t, err)
	statementXkgamma := &zkproofs.MulStatement{
		N: pkSender.N,
		X: Xgamma,
		Y: cA,
		C: Xkgamma,
	}
	valid := proof.Verify(statementXkgamma)
	assert.True(t, valid)
}
