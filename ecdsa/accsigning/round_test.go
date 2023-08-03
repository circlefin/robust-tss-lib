// Copyright 2023 Circle
//

package accsigning

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/tss"
)

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

// todo: uncomment unit tests

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

	modQ := common.ModInt(tss.EC().Params().N)
	for i, round := range round3s {
		for j, _ := range parties {
			assert.NotNil(t, round.temp.D[j])
		}
		assert.NotNil(t, round.temp.delta[i])
		assert.True(t, modQ.IsCongruent(round.temp.delta[i], round.temp.d))
	}

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
/*
	modQ := common.ModInt(tss.EC().Params().N)


	finalDelta := round5s[0].temp.finalDelta
	finalDeltaInv := round5s[0].temp.finalDeltaInv
	assert.True(t, modQ.IsMultInverse(finalDelta, finalDeltaInv))
	rx := round5s[0].temp.rx
	ry := round5s[0].temp.ry
	bigR := round5s[0].temp.bigR
	assert.Equal(t, 0, rx.Cmp(bigR.X()))
	assert.Equal(t, 0, ry.Cmp(bigR.Y()))
    m := round5s[0].temp.m

	zero := big.NewInt(0)
	k := zero
	s := zero
	w := zero
	gamma := zero
	for _, round := range round5s {
	    assert.Equal(t, 0, finalDelta.Cmp(round.temp.finalDelta))
	    assert.Equal(t, 0, finalDeltaInv.Cmp(round.temp.finalDeltaInv))
	    assert.Equal(t, 0, rx.Cmp(round.temp.rx))
	    assert.Equal(t, 0, ry.Cmp(round.temp.ry))
	    assert.Equal(t, 0, m.Cmp(round.temp.m))
	    assert.True(t, bigR.Equals(round.temp.bigR))

	    k = modQ.Add(k, round.temp.k)
	    s = modQ.Add(s, round.temp.si)
        w = modQ.Add(w, round.temp.w)
        gamma = modQ.Add(gamma, round.temp.gamma)
	}

    expectedS := modQ.Add(modQ.Mul(m, k), modQ.Mul(rx, modQ.Mul(k, w)))
    assert.Equal(t, 0, expectedS.Cmp(s))

    // checking pk
	pk, err := crypto.NewECPoint(
		round5s[0].Params().EC(),
		round5s[0].key.ECDSAPub.X(),
		round5s[0].key.ECDSAPub.Y(),
	)
	assert.NoError(t, err)
	for _, round := range round5s {
    	prodBigW := round.temp.bigWs[0]
	    for i, bigW := range round.temp.bigWs {
	        if i == 0 {
	            continue
	        }
	        prodBigW, err = prodBigW.Add(bigW)
	        assert.NoError(t, err)
	    }
	    assert.True(t, pk.Equals(prodBigW))
	}

	assert.Equal(t, 0, parties[0].temp.m.Cmp(out.M))
    assert.Equal(t, len(parties), len(out.Si))
	assert.Equal(t, 0, round5s[0].key.ECDSAPub.X().Cmp(out.PkX))
	assert.Equal(t, 0, round5s[0].key.ECDSAPub.Y().Cmp(out.PkY))
	expectedK := big.NewInt(333)
	for i, party := range parties {
	    assert.Equal(t, 0, party.temp.k.Cmp(expectedK))
	    assert.Equal(t, 0, out.Ks[i].Cmp(expectedK))
	    assert.Equal(t, 0, out.Ws[i].Cmp(party.temp.w))
        assert.True(t, out.R.Equals(party.temp.bigR))
	    assert.True(t, modQ.IsCongruent(party.temp.gamma, out.Gamma[i]))
	    assert.True(t, party.temp.pointGamma[i].Equals(out.PointGamma[i]))
//	    assert.Equal(t, 0, out.Si[i].Cmp(party.temp.si)) // <-- diff
	    assert.Equal(t, 0, out.Sigma[i].Cmp(party.temp.sigma)) // same with fixed nuPrm
	    assert.Equal(t, 0, out.Theta.Cmp(party.temp.delta[i]))  // same with fixed betaPrm
	    assert.True(t, modQ.IsCongruent(party.temp.delta[i], out.Theta))  // same with fixed betaPrm
	}
	assert.Equal(t, 0, k.Cmp(out.K))

	assert.Equal(t, 0, parties[0].temp.finalDeltaInv.Cmp(out.ThetaInv))
	assert.Equal(t, 0, rx.Cmp(out.Rx))  // <-- diff
	assert.Equal(t, 0, ry.Cmp(out.Ry))  // <-- diff
	assert.Equal(t, 0, s.Cmp(out.SumS))  // <-- diff
    assert.True(t, modQ.IsCongruent(rx, out.Rx)) // <-- diff
    assert.True(t, modQ.IsCongruent(ry, out.Ry)) // <-- diff
    assert.True(t, modQ.IsCongruent(s, out.SumS)) // <-- diff
	assert.True(t, bigR.Equals(out.R))
	assert.Equal(t, 0, out.R.X().Cmp(out.Rx))
	assert.Equal(t, 0, out.R.Y().Cmp(out.Ry))
	assert.Equal(t, 0, out.R.X().Cmp(bigR.X()))
	assert.Equal(t, 0, out.R.Y().Cmp(bigR.Y()))
	assert.Equal(t, 0, rx.Cmp(bigR.X())) // <-- diff
	assert.Equal(t, 0, ry.Cmp(bigR.Y())) // <-- diff
	*/
}