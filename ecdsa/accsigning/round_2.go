// Copyright 2023 Circle

package accsigning

import (
	"errors"
	"fmt"
	"sync"

	errorspkg "github.com/pkg/errors"

	"github.com/bnb-chain/tss-lib/crypto/accmta"
	"github.com/bnb-chain/tss-lib/tss"
)

func (round *round2) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 2
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	round.ok[i] = true

	errChs := make(chan *tss.Error, (len(round.Parties().IDs())-1)*2)
	wg := sync.WaitGroup{}
	wg.Add((len(round.Parties().IDs()) - 1) * 2)
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		// todo: skip verification of Alice proof one of the times
		// BobRespondsP on share k * gamma, Bob's secret is w
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			if round.temp.signRound1Message1s[j] == nil {
			    errChs <- round.WrapError(fmt.Errorf("nil round1message1[%d]", j ))
			    return
			}
			r1msg := round.temp.signRound1Message1s[j].Content().(*SignRound1Message1)
			rangeProofAliceJ, err := r1msg.UnmarshalRangeProofAlice()
			if err != nil {
				errChs <- round.WrapError(errorspkg.Wrapf(err, "UnmarshalRangeProofAlice failed"), Pj)
				return
			}
			cA := r1msg.UnmarshalCA()
    		ringPedersenBobI := round.key.GetRingPedersen(i)
    		ringPedersenAliceJ := round.key.GetRingPedersen(j)
            beta, cGamma, _, proofP, err := accmta.BobRespondsP(
            	round.Params().EC(),
            	// Alice's public key
            	round.key.PaillierPKs[j],
            	// Bob's public key
            	round.key.PaillierPKs[i],
            	// Alice's proof
            	rangeProofAliceJ,
            	// Bob's secret
            	round.temp.gamma,
            	// Alice's encryption of a under pkA
            	cA,
            	// Alice's Ring Pedersen parameters
            	ringPedersenAliceJ,
            	// Bob's Ring Pedersen parameters
            	ringPedersenBobI,
            )

			// should be thread safe as these are pre-allocated
			round.temp.betas[j] = beta
			round.temp.c1jis[j] = cGamma
			round.temp.pi1jis[j] = proofP
			if err != nil {
				errChs <- round.WrapError(err, Pj)
			}
		}(j, Pj)
		// BobRespondsDL on share k*w, Bob's secret is w
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			if round.temp.signRound1Message1s[j] == nil {
			    errChs <- round.WrapError(fmt.Errorf("nil round1message1[%d]", j ))
			    return
			}
			r1msg := round.temp.signRound1Message1s[j].Content().(*SignRound1Message1)
			rangeProofAliceJ, err := r1msg.UnmarshalRangeProofAlice()
			if err != nil {
				errChs <- round.WrapError(errorspkg.Wrapf(err, "UnmarshalRangeProofAlice failed"), Pj)
				return
			}
 			cA := r1msg.UnmarshalCA()
     		ringPedersenBobI := round.key.GetRingPedersen(i)
     		ringPedersenAliceJ := round.key.GetRingPedersen(j)
            v, cW, _, proofDL, err := accmta.BobRespondsDL(
           	round.Params().EC(),
            	// Alice's public key
            	round.key.PaillierPKs[j],
            	// Bob's public key
            	round.key.PaillierPKs[i],
            	// Alice's proof
            	rangeProofAliceJ,
            	// Bob's secret
            	round.temp.w,
            	// Alice's encryption of a under pkA
            	cA,
            	// Alice's Ring Pedersen parameters
            	ringPedersenAliceJ,
            	// Bob's Ring Pedersen parameters
            	ringPedersenBobI,
            	// DL commitment to Bob's input b
            	round.temp.bigWs[i],
            )
			round.temp.vs[j] = v
			round.temp.c2jis[j] = cW
			round.temp.pi2jis[j] = proofDL
			if err != nil {
				errChs <- round.WrapError(err, Pj)
			}
		}(j, Pj)
	}
	// consume error channels; wait for goroutines
	wg.Wait()
	close(errChs)
	culprits := make([]*tss.PartyID, 0, len(round.Parties().IDs()))
	for err := range errChs {
		culprits = append(culprits, err.Culprits()...)
	}
	if len(culprits) > 0 {
		return round.WrapError(errors.New("failed to calculate Bob_mid or Bob_mid_wc"), culprits...)
	}
	// create and send messages
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		r2msg := NewSignRound2Message1(
			Pj, round.PartyID(), round.temp.c1jis[j], round.temp.c2jis[j], round.temp.pi1jis[j], round.temp.pi2jis[j])
		round.out <- r2msg
	}
	return nil
}

func (round *round2) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.signRound2Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *round2) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound2Message1); ok {
		return !msg.IsBroadcast()
	}
	return false
}

func (round *round2) NextRound() tss.Round {
	round.started = false
	return &round3{round}
}
