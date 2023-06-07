// Copyright 2023 Circle
//

package accsigning

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/btcsuite/btcd/btcec"
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


func setUp(level string) {
	if err := log.SetLogLevel("tss-lib", level); err != nil {
		panic(err)
	}
}

func setupParties(t *testing.T)  (
    params *tss.Parameters,
    parties []*LocalParty,
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
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan common.SignatureData, len(signPIDs))

	updater := test.SharedPartyUpdater

	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold)

		P := NewLocalParty(big.NewInt(42), params, keys[i], outCh, endCh).(*LocalParty)
		parties = append(parties, P)
	}
	return params, parties
}

func TestRound1(t *testing.T) {
    params, parties := setupParties(t)
	errCh := make(chan *tss.Error, len(parties))
	outCh := make(chan tss.Message, len(parties))
	endCh := make(chan common.SignatureData, len(parties))

    party := parties[0]
    round1 := accsigning.newRound1(params, party.key, party.data, party.temp, outCh, endCh)

    err := round1.Start()
    assert.NoError(t, err, "start")

    r1msg1 := make([]*NewSignRound1Message1, 0, len(parties))
    for j, Pj := range round1.Parties().IDs() {
        if j == 0 {
            continue
        }
        r1msg1[j] <- round1.out
    }
    r1msg2 <- round1.out
}