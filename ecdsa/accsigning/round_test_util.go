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
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/test"
	"github.com/bnb-chain/tss-lib/tss"
)

const (
	testParticipants = test.TestParticipants
	testThreshold    = test.TestThreshold
)

func SetUp(level string) {
	if err := log.SetLogLevel("tss-lib", level); err != nil {
		panic(err)
	}
}

func SetupParties(t *testing.T) (
	params []*tss.Parameters,
	parties []*LocalParty,
	outCh chan tss.Message,
) {
	SetUp("info")
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

	outCh = make(chan tss.Message, len(signPIDs)*len(signPIDs)*2)
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

func GetParsedMessage(t *testing.T, message tss.Message, expectedType string) tss.ParsedMessage {
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

func IsMessageType(msg tss.Message, expectedType string) bool {
	mType := msg.Type()
	return expectedType == mType
}

func AssertNoErrors(t *testing.T, errChs chan *tss.Error) {
	for err := range errChs {
		t.Logf("%v", err)
		AssertNoTssError(t, err)
	}
}

func AssertNoTssError(t *testing.T, err *tss.Error) {
	if err != nil {
		assert.False(t, true, err.Error())
	}
}

func DeliverMessages(t *testing.T, totalMessages int, parties []*LocalParty, outCh chan tss.Message) {
	errChs := make(chan *tss.Error, (len(parties) * 3))
	for num := 0; num < totalMessages; num += 1 {
		var msg tss.Message = <-outCh
		dest := msg.GetTo()
		if dest == nil || len(dest) == 0 {
			for recipient, _ := range parties {
				test.SharedPartyUpdater(parties[recipient], msg, errChs)
			}
		} else {
			test.SharedPartyUpdater(parties[dest[0].Index], msg, errChs)
		}
	}
	close(errChs)
	AssertNoErrors(t, errChs)
}

func RunRound1(t *testing.T, params []*tss.Parameters, parties []*LocalParty, outCh chan tss.Message) []*round1 {
	rounds := make([]*round1, len(parties))
	wg := sync.WaitGroup{}
	for j, party := range parties {
		wg.Add(1)
		go func(j int, party *LocalParty) {
			defer wg.Done()
			partyParams := params[j]
			rounds[j] = newRound1(partyParams, &party.keys, &party.data, &party.temp, party.out, party.end).(*round1)
			err := rounds[j].prepare()
			assert.NoError(t, err)
			tssError := rounds[j].Start()
			assert.Nil(t, tssError)
		}(j, party)
	}
	wg.Wait()

	// deliver all messages
	totalMessages := len(parties) * len(parties)
	DeliverMessages(t, totalMessages, parties, outCh)
	return rounds
}

func RunRound[InRound tss.Round, OutRound tss.Round](
	t *testing.T,
	params []*tss.Parameters,
	parties []*LocalParty,
	inrounds []InRound,
	totalMessages int,
	outCh chan tss.Message,
) []OutRound {
	outrounds := make([]OutRound, len(parties))
	for j, round := range inrounds {
		ok, tssErr := round.Update()
		assert.True(t, ok)
		assert.Nil(t, tssErr)
		outrounds[j] = round.NextRound().(OutRound)
	}

	wg := sync.WaitGroup{}
	for j, round := range outrounds {
		wg.Add(1)
		go func(j int, round OutRound) {
			defer wg.Done()
			tssError := round.Start()
			AssertNoTssError(t, tssError)
		}(j, round)
	}
	wg.Wait()
	DeliverMessages(t, totalMessages, parties, outCh)
	return outrounds
}
