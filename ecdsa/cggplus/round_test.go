// Copyright 2023 Circle
//

package cggplus

import (
	//	"fmt"
	"sync"
	"testing"

	//	"github.com/stretchr/testify/assert"

	//	"github.com/bnb-chain/tss-lib/common"
	//	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/tss"
)

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

/*
func TestRound2(t *testing.T) {
	params, parties, outCh, _, _, _ := SetupParties(t)
	t.Logf("round 1")
	round1s := RunRound1(t, params, parties, outCh)
	t.Logf("round 2")
	totalMessages := len(parties) * len(parties)
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
*/
/*
func TestRound3(t *testing.T) {
	params, parties, outCh, _, _, _ := SetupParties(t)
	t.Logf("round 1")
	round1s := RunRound1(t, params, parties, outCh)
	t.Logf("round 2")
	totalMessages := len(parties) * len(parties)
	round2s := RunRound[*round1, *round2](t, params, parties, round1s, totalMessages, outCh)
	t.Logf("round 3")
	round3s := RunRound[*round2, *round3](t, params, parties, round2s, len(parties), outCh)

	wg := sync.WaitGroup{}
	partyCount := len(parties)
	errChs := make(chan *tss.Error, partyCount*partyCount*partyCount)

	t.Logf("verifying")
	for _, round := range round3s {
		wg.Add(1)
		go func(round *round3) {
			defer wg.Done()
			nextRound := &round4{round}
			for sender := range nextRound.Parties().IDs() {
			    XDelta, _ := round3s[sender].ComputeXDelta()
			    XDeltaPrime, _ := nextRound.ComputeXDelta(sender, round3s[sender].temp.bigH)
			    assert.Equal(t, 0, XDelta.Cmp(XDeltaPrime))

			    r3msg := nextRound.temp.signRound3Messages[sender].Content().(*SignRound3Message)
                bigH := r3msg.UnmarshalBigH()
			    XDeltaPrimPrimee, _ := nextRound.ComputeXDelta(sender, bigH)
			    assert.Equal(t, 0, XDelta.Cmp(XDeltaPrimPrimee))
			}
    		nextRound.VerifyRound3Messages(errChs)
		}(round)
	}

	wg.Wait()
	close(errChs)
	AssertNoErrors(t, errChs)
}
*/
/*
func TestRound4(t *testing.T) {
	params, parties, outCh, _, _, _ := SetupParties(t)
	t.Logf("round 1")
	round1s := RunRound1(t, params, parties, outCh)
	t.Logf("round 2")
	totalMessages := len(parties) * len(parties)
	round2s := RunRound[*round1, *round2](t, params, parties, round1s, totalMessages, outCh)
	t.Logf("round 3")
	round3s := RunRound[*round2, *round3](t, params, parties, round2s, len(parties), outCh)
	t.Logf("round 4")
	_ = RunRound[*round3, *round4](t, params, parties, round3s, len(parties), outCh)

	// no need to verify output as round4 has empty message
}*/

func TestRound5(t *testing.T) {
	params, parties, outCh, _, _, _ := SetupParties(t)
	t.Logf("round 1")
	round1s := RunRound1(t, params, parties, outCh)
	t.Logf("round 2")
	totalMessages := len(parties) * len(parties)
	round2s := RunRound[*round1, *round2](t, params, parties, round1s, totalMessages, outCh)
	t.Logf("round 3")
	round3s := RunRound[*round2, *round3](t, params, parties, round2s, len(parties), outCh)
	t.Logf("round 4")
	round4s := RunRound[*round3, *round4](t, params, parties, round3s, len(parties), outCh)
	t.Logf("round 5")
	round5s := RunRound[*round4, *round5](t, params, parties, round4s, len(parties), outCh)

	t.Logf("verifying")
	wg := sync.WaitGroup{}
	partyCount := len(parties)
	errChs := make(chan *tss.Error, partyCount*partyCount*partyCount)
	for _, round := range round5s {
		wg.Add(1)
		go func(round *round5) {
			defer wg.Done()
			nextRound := &finalization{round}
			nextRound.VerifyRound5Messages(errChs)
		}(round)
	}

	wg.Wait()
	close(errChs)
	AssertNoErrors(t, errChs)
}

func testXDelta(t *testing.T, round *round4, i int) {
	for j := range round.Parties().IDs() {
		if j == i {
			continue
		}
		if round.temp.bigD[j][i] == nil {
			t.Logf("round[%d] bigD[%d][%d] nil", round.PartyID().Index, j, i)
		}
		if round.temp.bigF[i][j] == nil {
			t.Logf("round[%d] bigF[%d][%d] nil", round.PartyID().Index, i, j)
		}
	}
}

/*
func TestRound4(t *testing.T) {
	params, parties, outCh, _, _, _ := SetupParties(t)
	t.Logf("round 1")
	round1s := RunRound1(t, params, parties, outCh)
	t.Logf("round 2")
	totalMessages := len(parties) * len(parties)
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
	totalMessages := len(parties) * len(parties)
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

func TestRoundFinalization(t *testing.T) {
	//	params, parties, outCh, keys, signPIDs, p2pCtx := SetupParties(t)
	// _= signing.Run(t, keys, signPIDs, p2pCtx)
	params, parties, outCh, _, _, _ := SetupParties(t)

	t.Logf("round 1")
	round1s := RunRound1(t, params, parties, outCh)
	t.Logf("round 2")
	totalMessages := len(parties) * len(parties)
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
*/
