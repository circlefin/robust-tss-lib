// Copyright 2023 Circle
//

package accsigning

import (
	"math/big"
	"sync"
	"testing"

	"github.com/ipfs/go-log"
	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto/accmta"
	"github.com/bnb-chain/tss-lib/crypto/paillier"
	"github.com/bnb-chain/tss-lib/crypto/zkproofs"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/test"
	"github.com/bnb-chain/tss-lib/tss"
)

const (
	testParticipants = test.TestParticipants
	testThreshold    = test.TestThreshold
)

func setUp(level string) {
	if err := log.SetLogLevel("tss-lib", level); err != nil {
		panic(err)
	}
}

func setupParties(t *testing.T) (
	params []*tss.Parameters,
	parties []*LocalParty,
	outCh chan tss.Message,
) {
	setUp("info")
	threshold := testThreshold

	// PHASE: load keygen fixtures
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(signPIDs))

	// PHASE: signing
	// use a shuffled selection of the list of parties for this test
	p2pCtx := tss.NewPeerContext(signPIDs)
	parties = make([]*LocalParty, 0, len(signPIDs))

	outCh = make(chan tss.Message, len(signPIDs))
	endCh := make(chan common.SignatureData, len(signPIDs))

	//	updater := test.SharedPartyUpdater

	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		Pparams := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold)
		params = append(params, Pparams)
		P := NewLocalParty(big.NewInt(42), Pparams, keys[i], outCh, endCh).(*LocalParty)
		parties = append(parties, P)
	}
	return params, parties, outCh
}

func TestRound1(t *testing.T) {
	params, parties, outCh := setupParties(t)

	party := parties[0]
	partyParams := params[0]
	round1 := newRound1(partyParams, &party.keys, &party.data, &party.temp, party.out, party.end).(*round1)
	err := round1.prepare()
	assert.NoError(t, err)
	tssError := round1.Start()
	assert.Nil(t, tssError)

	r1msg1 := make([]SignRound1Message1, len(parties))
	for j, _ := range parties {
		if j == 0 {
			continue
		}
		var msg tss.Message = <-outCh
		parsedMessage := GetSignRoundMessage(t, msg, "binance.tsslib.ecdsa.accsigning.SignRound1Message1")
		content, ok := parsedMessage.Content().(*SignRound1Message1)
		assert.True(t, ok, "could not get content")
		assert.NotNil(t, content)
		r1msg1[j] = *content
	}
	var msg tss.Message = <-outCh
	parsedMessage := GetSignRoundMessage(t, msg, "binance.tsslib.ecdsa.accsigning.SignRound1Message2")
	content, ok := parsedMessage.Content().(*SignRound1Message2)
	assert.True(t, ok, "could not get content")
	assert.NotNil(t, content)
	r1msg2 := *content

	for j, receiver := range parties {
		if j == 0 {
			continue
		}
		ValidateSignRound1Messages(t, round1, &r1msg1[j], &r1msg2, party, receiver)
	}
}

func ValidateSignRound1Messages(t *testing.T, round *round1, msg1 *SignRound1Message1, msg2 *SignRound1Message2, sender, receiver *LocalParty) {
	ValidateRound1RangeProofAlice(t, msg1, msg2, &sender.keys.PaillierSK.PublicKey, receiver.keys.RingPedersen())
	ValidateRound1ProofXK(t, msg1, msg2, &sender.keys.PaillierSK.PublicKey, receiver.keys.RingPedersen())
	ValidateRound1ProofXGamma(t, msg1, msg2, &sender.keys.PaillierSK.PublicKey, receiver.keys.RingPedersen())
	ValidateRound1ProofXKw(t, round, msg1, msg2, &sender.keys.PaillierSK.PublicKey, receiver.keys.RingPedersen())
	ValidateRound1ProofXKGamma(t, msg2, &sender.keys.PaillierSK.PublicKey)
}

func ValidateRound1RangeProofAlice(t *testing.T, msg1 *SignRound1Message1, msg2 *SignRound1Message2, pkSender *paillier.PublicKey, rpReceiver *zkproofs.RingPedersenParams) {
	cA := msg1.UnmarshalCA()
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
	Xk := msg2.UnmarshalXK()
	proof, err := msg1.UnmarshalProofXK()
	assert.NoError(t, err)
	statementXk := &zkproofs.EncStatement{
		EC: tss.EC(),
		N0: pkSender.N,
		K:  Xk,
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

func ValidateRound1ProofXKw(t *testing.T, round *round1, msg1 *SignRound1Message1, msg2 *SignRound1Message2, pkSender *paillier.PublicKey, rpReceiver *zkproofs.RingPedersenParams) {
	Xk := msg2.UnmarshalXK()
	Xkw := msg2.UnmarshalXKw()
	bigW := round.temp.bigWs[round.PartyID().Index]
	proof, err := msg1.UnmarshalProofXKw(tss.EC())
	assert.NoError(t, err)
	statementXkw := &zkproofs.MulStarStatement{
		Ell: zkproofs.GetEll(round.Params().EC()),
		N0:  pkSender.N,
		C:   Xk,
		D:   Xkw,
		X:   bigW,
	}
	valid := proof.Verify(statementXkw, rpReceiver)
	assert.True(t, valid)
}

func ValidateRound1ProofXKGamma(t *testing.T, msg2 *SignRound1Message2, pkSender *paillier.PublicKey) {
	Xgamma := msg2.UnmarshalXGamma()
	Xk := msg2.UnmarshalXK()
	Xkgamma := msg2.UnmarshalXKGamma()
	proof, err := msg2.UnmarshalProofXKgamma()
	assert.NoError(t, err)
	statementXkgamma := &zkproofs.MulStatement{
		N: pkSender.N,
		X: Xgamma,
		Y: Xk,
		C: Xkgamma,
	}
	valid := proof.Verify(statementXkgamma)
	assert.True(t, valid)
}

func TestRound2(t *testing.T) {
	params, parties, outCh := setupParties(t)

	// perform round 1
	round1s := make([]*round1, len(parties))
	wg := sync.WaitGroup{}
	wg.Add(len(parties))
	for i, party := range parties {
		go func(i int, party *LocalParty) {
			defer wg.Done()
			partyParams := params[i]
			round1s[i] = newRound1(partyParams, &party.keys, &party.data, &party.temp, party.out, party.end).(*round1)
			err := round1s[i].prepare()
			assert.NoError(t, err)
			tssError := round1s[i].Start()
			assert.Nil(t, tssError)
		}(i, party)
	}

	// deliver messages form party i to party[0]
	// there are len(parties)^2 messages on the outCh
	for msgIndex := 0; msgIndex < len(parties)*len(parties); msgIndex++ {
		var msg tss.Message = <-outCh
		if msg.IsBroadcast() {
			senderIndex := msg.GetFrom().Index
			if senderIndex != 0 {
				parsedMessage := GetSignRoundMessage(t, msg, "binance.tsslib.ecdsa.accsigning.SignRound1Message2")
				round1s[0].temp.signRound1Message2s[senderIndex] = parsedMessage
			}
		} else {
			senderIndex := msg.GetFrom().Index
			receiverIndex := msg.GetTo()[0].Index
			if receiverIndex == 0 && senderIndex != 0 {
				parsedMessage := GetSignRoundMessage(t, msg, "binance.tsslib.ecdsa.accsigning.SignRound1Message1")
				round1s[0].temp.signRound1Message1s[senderIndex] = parsedMessage
			}
		}
	}

	// run round 2 on party 0
	ok, tssErr := round1s[0].Update()
	assert.True(t, ok)
	assert.Nil(t, tssErr)
	if tssErr != nil {
		assert.NoError(t, tssErr.Cause())
	}
	round2 := round1s[0].NextRound()
	tssErr = round2.Start()
	assert.Nil(t, tssErr)
	if tssErr != nil {
		assert.NoError(t, tssErr.Cause())
	}

	// verify the messages from party 0
	// there are len(parties)-1 messages on the outCh
	for msgIndex := 0; msgIndex < len(parties)-1; msgIndex++ {
		var msg tss.Message = <-outCh
		senderIndexJ := msg.GetFrom().Index
		assert.Equal(t, 0, senderIndexJ)
		receiverIndex := msg.GetTo()[0].Index
		parsedMessage := GetSignRoundMessage(t, msg, "binance.tsslib.ecdsa.accsigning.SignRound2Message1")
		assert.NotNil(t, parsedMessage)

		//unmarshall the statements
		r2msg := parsedMessage.Content().(*SignRound2Message1)
		cGamma := r2msg.UnmarshalCGamma()
		cW := r2msg.UnmarshalCW()
		bobProofP, err := r2msg.UnmarshalProofP()
		assert.NoError(t, err)
		assert.NotNil(t, bobProofP)
		assert.NotNil(t, bobProofP.Proof)
		bobProofDL, err := r2msg.UnmarshalProofDL(tss.EC())
		assert.NotNil(t, bobProofDL)
		assert.NotNil(t, bobProofDL.Proof)
		assert.NoError(t, err)

		// the verifier is receiverIndex who plays Alice
		rpA := round1s[receiverIndex].key.GetRingPedersen(receiverIndex)
		statementP := &zkproofs.AffPStatement{
			C:        round1s[receiverIndex].temp.cis[senderIndexJ],          // Alice's ciphertext
			D:        cGamma,                                                 // affine transform of Alice's ciphertext: cA(*)b + betaPrm
			X:        bobProofP.X,                                            // encryption of b using Bob's public key
			Y:        bobProofP.Y,                                            // encryption of betaPrm
			N0:       round1s[receiverIndex].key.PaillierSK.N,                // Alice's public key
			N1:       round1s[receiverIndex].key.PaillierPKs[senderIndexJ].N, // Bob's public key
			Ell:      zkproofs.GetEll(tss.EC()),                              // max size of plaintext
			EllPrime: zkproofs.GetEll(tss.EC()),                              // max size of plaintext
			EC:       tss.EC(),                                               // elliptic curve
		}
		assert.True(t, bobProofP.Proof.Verify(statementP, rpA))

		statementDL := &zkproofs.AffGStatement{
			C:        round1s[receiverIndex].temp.cis[senderIndexJ],          // Alice's ciphertext cA to senderIndexJ
			D:        cW,                                                     // affine transform of Alice's ciphertext: cA(*)b + betaPrm
			X:        round1s[receiverIndex].temp.bigWs[senderIndexJ],        // Bob's bigW
			Y:        bobProofDL.Y,                                           // encryption of betaPrm
			N0:       round1s[receiverIndex].key.PaillierSK.N,                // Alice's public key
			N1:       round1s[receiverIndex].key.PaillierPKs[senderIndexJ].N, // Bob's public key
			Ell:      zkproofs.GetEll(tss.EC()),                              // max size of plaintext
			EllPrime: zkproofs.GetEll(tss.EC()),                              // max size of plaintext
		}
		assert.True(t, bobProofDL.Proof.Verify(statementDL, rpA))
	}
}

func GetSignRoundMessage(t *testing.T, message tss.Message, expectedType string) tss.ParsedMessage {
	wireBytes, routing, err := message.WireBytes()
	assert.NoError(t, err)
	mType := message.Type()
	assert.Equal(t, expectedType, mType)
	from := routing.From
	isBroadcast := message.IsBroadcast()
	parsedMessage, err := tss.ParseWireMessage(wireBytes, from, isBroadcast)
	assert.NoError(t, err)
	assert.True(t, parsedMessage.ValidateBasic())
	return parsedMessage
}
