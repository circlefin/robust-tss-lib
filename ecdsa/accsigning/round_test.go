// Copyright 2023 Circle
//

package accsigning

import (
	"fmt"
//	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
//	"github.com/bnb-chain/tss-lib/tss"
)
/*
*  Uncomment test to check individual round
*

func TestHomoAddLimit(t *testing.T) {
	keys, _, err := keygen.LoadKeygenTestFixturesRandomSet(1, 1)
	assert.NoError(t, err)

	q := tss.EC().Params().N
	pk := keys[0].PaillierSK.PublicKey
	sk := keys[0].PaillierSK
	modQ := common.ModInt(q)
	modN := common.ModInt(pk.N)

	val := common.GetRandomPositiveInt(q)
	sumQ := val
	sumN := val
	cVal, _ := pk.Encrypt(val)
	cSum := cVal
	assert.NoError(t, err)
	for i := 0; i < 60; i++ {
		dSum, err := sk.Decrypt(cSum)
		assert.NoError(t, err)
		assert.True(t, modQ.IsCongruent(sumQ, dSum), fmt.Sprintf("error modQ %d", i))
		assert.True(t, modQ.IsCongruent(sumN, dSum), fmt.Sprintf("error modN %d", i))

		sumQ = modQ.Add(sumQ, val)
		sumN = modN.Add(sumN, val)
		cSum, err = pk.HomoAdd(cSum, cVal)
		assert.NoError(t, err)
	}
}

func TestRound1(t *testing.T) {
	params, parties, outCh, _, _, _ := SetupParties(t)
	rounds := RunRound1(t, params, parties, outCh)

	wg := sync.WaitGroup{}
	partyCount := len(parties)
	errChs := make(chan *tss.Error, partyCount*partyCount*3)
	for _, round := range rounds {
		wg.Add(1)
		go func(round *round1) {
			defer wg.Done()
			nextRound := &round2{round}
			nextRound.VerifyRound1Messages(errChs)
		}(round)
	}
	wg.Wait()
	close(errChs)
	AssertNoErrors(t, errChs)

}

func TestRound2(t *testing.T) {
	params, parties, outCh, _, _, _ := SetupParties(t)
	t.Logf("round 1")
	round1s := RunRound1(t, params, parties, outCh)
	t.Logf("round 2")
	totalMessages := len(parties) * (len(parties) - 1)
	round2s := RunRound[*round1, *round2](t, params, parties, round1s, totalMessages, outCh)

	wg := sync.WaitGroup{}
	partyCount := len(parties)
	errChs := make(chan *tss.Error, partyCount*partyCount*partyCount)
	for _, round := range round2s {
		wg.Add(1)
		go func(round *round2) {
			defer wg.Done()
			nextRound := &round3{round}
			nextRound.VerifyRound2Messages(errChs)
		}(round)
	}
	wg.Wait()
	close(errChs)
	AssertNoErrors(t, errChs)
}

func TestRound3(t *testing.T) {
	params, parties, outCh, _, _, _ := SetupParties(t)
	t.Logf("round 1")
	round1s := RunRound1(t, params, parties, outCh)
	t.Logf("round 2")
	totalMessages := len(parties) * (len(parties) - 1)
	round2s := RunRound[*round1, *round2](t, params, parties, round1s, totalMessages, outCh)
	t.Logf("round 3")
	round3s := RunRound[*round2, *round3](t, params, parties, round2s, len(parties), outCh)
	assert.NotNil(t, round3s)

	wg := sync.WaitGroup{}
	partyCount := len(parties)
	errChs := make(chan *tss.Error, partyCount*partyCount*partyCount)
	for _, round := range round3s {
		wg.Add(1)
		go func(round *round3) {
			defer wg.Done()
			nextRound := &round4{round}
			nextRound.VerifyRound3Messages(errChs)
		}(round)
	}
	wg.Wait()
	close(errChs)
	AssertNoErrors(t, errChs)
}

func TestRound4(t *testing.T) {
	params, parties, outCh, _, _, _ := SetupParties(t)
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
			go func(round *round4) {
				defer wg.Done()
				nextRound := &round5{round}
				err := nextRound.VerifyRound4Messages()
				AssertNoTssError(t, err)
			}(round)
		}
	}
	wg.Wait()
}

func TestRound5(t *testing.T) {
	params, parties, outCh, _, _, _ := SetupParties(t)

	t.Logf("round 1")
	round1s := RunRound1(t, params, parties, outCh)
	t.Logf("round 2")
	totalMessages := len(parties) * (len(parties) - 1)
	round2s := RunRound[*round1, *round2](t, params, parties, round1s, totalMessages, outCh)
	t.Logf("round 3")
	round3s := RunRound[*round2, *round3](t, params, parties, round2s, len(parties), outCh)
	t.Logf("round 4")
	round4s := RunRound[*round3, *round4](t, params, parties, round3s, len(parties), outCh)
	t.Logf("round 5")
	round5s := RunRound[*round4, *round5](t, params, parties, round4s, len(parties), outCh)

	wg := sync.WaitGroup{}
	for i, round := range round5s {
		for j, _ := range round.Parties().IDs() {
			if i == j {
				continue
			}

			wg.Add(1)
			go func(round *round5) {
				defer wg.Done()
				nextRound := &finalization{round}
				err := nextRound.VerifyRound5Messages()
				AssertNoTssError(t, err)
			}(round)
		}
	}
	wg.Wait()
}
*/

func TestRoundFinalization(t *testing.T) {
	//	params, parties, outCh, keys, signPIDs, p2pCtx := SetupParties(t)
	// _= signing.Run(t, keys, signPIDs, p2pCtx)
	params, parties, outCh, _, _, _ := SetupParties(t)

	t.Logf("round 1")
	round1s := RunRound1(t, params, parties, outCh)
	t.Logf("round 2")
	totalMessages := len(parties) * (len(parties) - 1)
	round2s := RunRound[*round1, *round2](t, params, parties, round1s, totalMessages, outCh)
	t.Logf("round 3")
	round3s := RunRound[*round2, *round3](t, params, parties, round2s, len(parties), outCh)
	t.Logf("round 4")
	round4s := RunRound[*round3, *round4](t, params, parties, round3s, len(parties), outCh)
	t.Logf("round 5")
	round5s := RunRound[*round4, *round5](t, params, parties, round4s, len(parties), outCh)
	t.Logf("finalize")
	_ = RunRound[*round5, *finalization](t, params, parties, round5s, len(parties), outCh)
}
