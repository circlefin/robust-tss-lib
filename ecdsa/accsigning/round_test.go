// Copyright 2023 Circle
//

package accsigning

import (
	"math/big"
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

func setupParties(t *testing.T)  (
    params []*tss.Parameters,
    parties []*LocalParty,
    outCh chan tss.Message,
){
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

//	errCh := make(chan *tss.Error, len(signPIDs))
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

    r1msg1 := make([] SignRound1Message1, len(parties))
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
	    K: Xk,
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
	    K: Xgamma,
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
        N0: pkSender.N,
        C: Xk,
        D: Xkw,
        X: bigW,
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


func GetSignRoundMessage(t *testing.T, message tss.Message, expectedType string) tss.ParsedMessage {
    wireBytes, routing, err := message.WireBytes()
    assert.NoError(t, err)
    mType :=  message.Type()
    assert.Equal(t, expectedType, mType)
	from := routing.From
    isBroadcast := message.IsBroadcast()
    parsedMessage, err := tss.ParseWireMessage(wireBytes, from, isBroadcast)
    assert.NoError(t, err)
    assert.True(t, parsedMessage.ValidateBasic())
    return parsedMessage
}

