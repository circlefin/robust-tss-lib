// Copyright 2023 Circle
//

package accsigning

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto/accmta"
	"github.com/bnb-chain/tss-lib/crypto/paillier"
	"github.com/bnb-chain/tss-lib/crypto/zkproofs"
	"github.com/bnb-chain/tss-lib/tss"
)

// todo: uncomment unit tests

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
	t.Logf("round 1")
	round1s := RunRound1(t, params, parties, outCh)
	t.Logf("round 2")
	totalMessages := len(parties) * (len(parties) - 1)
	round2s := RunRound[*round1, *round2](t, params, parties, round1s, totalMessages, outCh)

	wg := sync.WaitGroup{}
	for verifier, _ := range parties {
		for sender, _ := range parties {
			for recipient, _ := range parties {
				if sender == verifier || sender == recipient {
					continue
				}
				wg.Add(1)
				go func(verifier, sender, recipient int) {
					defer wg.Done()
					log := fmt.Sprintf("[%d][%d][%d]", verifier, sender, recipient)
					assert.NotNil(t, round2s[verifier].temp.signRound2Messages[sender][recipient], log)
					msg := round2s[verifier].temp.signRound2Messages[sender][recipient].Content().(*SignRound2Message)
					ValidateSignRound2Message(t, round2s[verifier], sender, verifier, msg)
					return
				}(verifier, sender, recipient)
			}
		}
	}
	wg.Wait()
}

func TestRound3(t *testing.T) {
	params, parties, outCh := SetupParties(t)
	t.Logf("round 1")
	round1s := RunRound1(t, params, parties, outCh)
	t.Logf("round 2")
	totalMessages := len(parties) * (len(parties) - 1)
	round2s := RunRound[*round1, *round2](t, params, parties, round1s, totalMessages, outCh)
	t.Logf("round 3")
	round3s := RunRound[*round2, *round3](t, params, parties, round2s, len(parties), outCh)
	assert.NotNil(t, round3s)

	wg := sync.WaitGroup{}
	q := tss.EC().Params().N
	for i, round := range round3s {
		delta := round.temp.delta[i]
		D := round.temp.D[i]
		d, err := round.key.PaillierSK.Decrypt(D)
		assert.NoError(t, err)
		assert.True(t, common.ModInt(q).Congruent(delta, d))

		for _, oround := range round3s {
			assert.NotNil(t, oround.temp.D[i])
			assert.Equal(t, 0, D.Cmp(oround.temp.D[i]))
		}

		for sender, _ := range round.Parties().IDs() {
			r3msg := round.temp.signRound3Messages[sender].Content().(*SignRound3Message)
			proofs, _ := r3msg.UnmarshalProof(tss.EC())
			for receiver, proof := range proofs {
				if receiver == sender {
					assert.True(t, proof.IsNil(), fmt.Sprintf("verify[%d][%d]", sender, receiver))
				} else {
					assert.False(t, proof.IsNil(), fmt.Sprintf("verify[%d][%d]", sender, receiver))
				}
			}
		}

		for j, _ := range round.Parties().IDs() {
			if i == j {
				continue
			}

			wg.Add(1)
			go func(receiver, sender int, round *round3) {
				defer wg.Done()
				r3msg := round.temp.signRound3Messages[sender].Content().(*SignRound3Message)
				proof, err := r3msg.UnmarshalProof(tss.EC())
				assert.NoError(t, err)
				delta := r3msg.UnmarshalDelta()
				assert.Equal(t, 0, delta.Cmp(round3s[sender].temp.delta[sender]), fmt.Sprintf("verify[%d][%d]", sender, receiver))
				assert.Equal(t, 0, round.temp.D[sender].Cmp(round3s[sender].temp.D[sender]), fmt.Sprintf("verify[%d][%d]", sender, receiver))
				pkj := round.key.PaillierPKs[sender]
				statement := &zkproofs.DecStatement{
					Q:   round.Params().EC().Params().N,
					Ell: zkproofs.GetEll(round.Params().EC()),
					N0:  pkj.N,
					C:   round.temp.D[sender],
					X:   delta,
				}
				rp := round.key.GetRingPedersen(receiver)
				assert.True(t, proof[receiver].Verify(statement, rp), fmt.Sprintf("verify[%d][%d]", sender, receiver))
			}(i, j, round)
		}
	}

	for i, _ := range round3s[0].Parties().IDs() {
		for j, _ := range round3s[0].Parties().IDs() {
			if i == j {
				continue
			}
			assert.NotNil(t, round3s[0].temp.cAlpha[i][j], fmt.Sprintf("cAlpha[%d][%d]", i, j))
			assert.NotNil(t, round3s[0].temp.cBetaPrm[i][j], fmt.Sprintf("cBetaPrm[%d][%d]", i, j))
			assert.NotNil(t, round3s[0].temp.cMu[i][j], fmt.Sprintf("cMu[%d][%d]", i, j))
			assert.NotNil(t, round3s[0].temp.cNuPrm[i][j], fmt.Sprintf("cNuPrm[%d][%d]", i, j))
		}
	}
	wg.Wait()
}

func TestRound4(t *testing.T) {
	params, parties, outCh := SetupParties(t)
	t.Logf("round 1")
	round1s := RunRound1(t, params, parties, outCh)
	t.Logf("round 2")
	totalMessages := len(parties) * (len(parties) - 1)
	round2s := RunRound[*round1, *round2](t, params, parties, round1s, totalMessages, outCh)
	t.Logf("round 3")
	round3s := RunRound[*round2, *round3](t, params, parties, round2s, len(parties), outCh)
	t.Logf("round 4")
	round4s := RunRound[*round3, *round4](t, params, parties, round3s, len(parties), outCh)

	wg := sync.WaitGroup{}
	for i, round := range round4s {
		for j, _ := range round.Parties().IDs() {
			if i == j {
				continue
			}

			wg.Add(1)
			go func(receiver, sender int, round *round4) {
				defer wg.Done()
				r4msg := round.temp.signRound4Messages[sender].Content().(*SignRound4Message)
				proof, err := r4msg.UnmarshalProof(round.Params().EC())
				assert.NoError(t, err)
				Gamma, err := r4msg.UnmarshalGamma(round.Params().EC())
				assert.NoError(t, err)
				assert.True(t, Gamma.Equals(round4s[sender].temp.pointGamma[sender]), fmt.Sprintf("verify[%d][%d]", sender, receiver))
				pkj := round.key.PaillierPKs[sender]
				statement := &zkproofs.LogStarStatement{
					Ell: zkproofs.GetEll(round.Params().EC()),
					N0:  pkj.N,
					C:   round.temp.Xgamma[sender],
					X:   Gamma,
				}
				rp := round.key.GetRingPedersen(receiver)
				assert.False(t, proof[receiver].IsNil())
				assert.True(t, proof[receiver].Verify(statement, rp), fmt.Sprintf("verify[%d][%d]", sender, receiver))
			}(i, j, round)
		}
	}
	wg.Wait()
}

func ValidateSignRound2Message(t *testing.T, round *round2, sender, verifier int, msg *SignRound2Message) {
	assert.NotNil(t, msg)
	recipient := msg.UnmarshalRecipient()
	cAlpha := msg.UnmarshalCAlpha()
	cBetaPrm := msg.UnmarshalCBetaPrm()
	cB := round.temp.Xgamma[sender]
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
		C:        cA,                                 // Alice's ciphertext
		D:        cAlpha,                             // affine transform of Alice's ciphertext: cA(*)b + betaPrm
		X:        cB,                                 // encryption of b using Bob's public key
		Y:        cBetaPrm,                           // encryption of betaPrm
		N0:       round.key.PaillierPKs[recipient].N, // Alice's public key
		N1:       round.key.PaillierPKs[sender].N,    // Bob's public key
		Ell:      zkproofs.GetEll(tss.EC()),          // max size of plaintext
		EllPrime: zkproofs.GetEll(tss.EC()),          // max size of plaintext
		EC:       tss.EC(),                           // elliptic curve
	}
	assert.NotNil(t, statementP.C)
	assert.True(t, proofPs[verifier].Verify(statementP, rpV))

	statementDL := &zkproofs.AffGStatement{
		C:        cA,                                 // Alice's ciphertext
		D:        cMu,                                // affine transform of Alice's ciphertext: cA(*)b + betaPrm
		X:        round.temp.bigWs[sender],           // Bob's bigW
		Y:        cNuPrm,                             // encryption of nuPrm
		N0:       round.key.PaillierPKs[recipient].N, // Alice's public key
		N1:       round.key.PaillierPKs[sender].N,    // Bob's public key
		Ell:      zkproofs.GetEll(tss.EC()),          // max size of plaintext
		EllPrime: zkproofs.GetEll(tss.EC()),          // max size of plaintext
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
