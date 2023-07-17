// Copyright 2023 Circle

package accsigning

import (
	"errors"
	"fmt"
	"sync"

	errorspkg "github.com/pkg/errors"

	"github.com/bnb-chain/tss-lib/crypto/accmta"
	//	"github.com/bnb-chain/tss-lib/crypto/paillier"
	"github.com/bnb-chain/tss-lib/crypto/zkproofs"
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

	errChs := make(chan *tss.Error, (len(round.Parties().IDs())-1)*3)
	wg := sync.WaitGroup{}
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}

		wg.Add(3)
		go round.Round2Verify(j, Pj, &wg, errChs)
		go round.BobRespondsP(j, Pj, &wg, errChs)
		go round.BobRespondsDL(j, Pj, &wg, errChs)
	}
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
		r2msg := NewSignRound2Message(
			Pj, round.PartyID(),
			round.temp.cAlpha[i][j],
			round.temp.cBetaPrm[i][j],
			round.temp.cMu[i][j],
			round.temp.cNuPrm[i][j],
			round.temp.proofP[i][j], round.temp.proofDL[i][j])
		round.out <- r2msg
	}
	return nil
}

func (round *round2) Round2Verify(j int, Pj *tss.PartyID, wg *sync.WaitGroup, errChs chan *tss.Error) {
	defer wg.Done()
	i := round.PartyID().Index

	if round.temp.signRound1Message1s[j] == nil {
		errChs <- round.WrapError(fmt.Errorf("nil round1message1[%d]", j))
		return
	}
	r1msg1 := round.temp.signRound1Message1s[j].Content().(*SignRound1Message1)
	proofXK, err := r1msg1.UnmarshalProofXK()
	if err != nil {
		errChs <- round.WrapError(fmt.Errorf("error parsing r1msg1[%d]", j))
		return
	}
	proofXgamma, err := r1msg1.UnmarshalProofXGamma()
	if err != nil {
		errChs <- round.WrapError(fmt.Errorf("error parsing r1msg1[%d]", j))
		return
	}
	proofXkw, err := r1msg1.UnmarshalProofXKw(round.Params().EC())
	if err != nil {
		errChs <- round.WrapError(fmt.Errorf("error parsing r1msg1[%d]", j))
		return
	}
	r1msg2 := round.temp.signRound1Message2s[j].Content().(*SignRound1Message2)
	round.temp.cA[j] = r1msg2.UnmarshalCA()
	proofXkgamma, err := r1msg2.UnmarshalProofXKgamma()
	if err != nil {
		errChs <- round.WrapError(fmt.Errorf("error parsing r1msg1[%d]", j))
		return
	}
	round.temp.Xgamma[j] = r1msg2.UnmarshalXGamma()
	round.temp.Xkgamma[j] = r1msg2.UnmarshalXKGamma()
	Xkw := r1msg2.UnmarshalXKw()
	rp := round.key.GetRingPedersen(i)

	paillierPK := round.key.PaillierPKs[j]
	bigW := round.temp.bigWs[j]
	statementXk := &zkproofs.EncStatement{
		EC: round.Params().EC(),
		N0: paillierPK.N,
		K:  round.temp.cA[j],
	}
	statementXgamma := &zkproofs.EncStatement{
		EC: round.Params().EC(),
		N0: paillierPK.N,
		K:  round.temp.Xgamma[j],
	}
	statementXkgamma := &zkproofs.MulStatement{
		N: paillierPK.N,
		X: round.temp.Xgamma[j],
		Y: round.temp.cA[j],
		C: round.temp.Xkgamma[j],
	}
	statementXkw := &zkproofs.MulStarStatement{
		Ell: zkproofs.GetEll(round.Params().EC()),
		N0:  paillierPK.N,
		C:   round.temp.cA[j],
		D:   Xkw,
		X:   bigW,
	}

	if !proofXK.Verify(statementXk, rp) ||
		!proofXgamma.Verify(statementXgamma, rp) ||
		!proofXkgamma.Verify(statementXkgamma) ||
		!proofXkw.Verify(statementXkw, rp) {
		errChs <- round.WrapError(fmt.Errorf("Failed to verify proofs from [%d]", j))
		return
	}
	return
}

func (round *round2) BobRespondsP(j int, Pj *tss.PartyID, wg *sync.WaitGroup, errChs chan *tss.Error) {
	defer wg.Done()
	i := round.PartyID().Index
	if round.temp.signRound1Message1s[j] == nil {
		errChs <- round.WrapError(fmt.Errorf("nil round1message1[%d]", j))
		return
	}
	r2msg := round.temp.signRound1Message2s[j].Content().(*SignRound1Message2)
	cA := r2msg.UnmarshalCA()

	r1msg := round.temp.signRound1Message1s[j].Content().(*SignRound1Message1)
	rangeProofAliceJ, err := r1msg.UnmarshalRangeProofAlice()
	if err != nil {
		errChs <- round.WrapError(errorspkg.Wrapf(err, "UnmarshalRangeProofAlice failed"), Pj)
		return
	}

	ringPedersenBobI := round.key.GetRingPedersen(i)
	rpVs := round.key.GetAllRingPedersen()
	rpVs[i] = nil
	beta, cAlpha, cBetaPrm, proofs, err := accmta.BobRespondsP(
		round.Params().EC(),
		// Alice's public key
		round.key.PaillierPKs[j],
		// Bob's private key
		round.key.PaillierSK,
		// Alice's proof
		rangeProofAliceJ,
		// Bob's encrypted secret gamma
		round.temp.Xgamma[i],
		// Alice's encryption of a under pkA
		cA,
		// Verifier's Ring Pedersen parameters
		rpVs,
		// Bob's Ring Pedersen parameters
		ringPedersenBobI,
	)

	// should be thread safe as these are pre-allocated
	round.temp.beta[j] = beta
	round.temp.cAlpha[i][j] = cAlpha
	round.temp.cBetaPrm[i][j] = cBetaPrm
	round.temp.proofP[i][j] = proofs
	if err != nil {
		errChs <- round.WrapError(err, Pj)
	}
}

// BobRespondsDL on share k*w, Bob's secret is w
func (round *round2) BobRespondsDL(j int, Pj *tss.PartyID, wg *sync.WaitGroup, errChs chan *tss.Error) {
	defer wg.Done()
	i := round.PartyID().Index
	if round.temp.signRound1Message1s[j] == nil {
		errChs <- round.WrapError(fmt.Errorf("nil round1message1[%d]", j))
		return
	}
	r2msg := round.temp.signRound1Message2s[j].Content().(*SignRound1Message2)
	cA := r2msg.UnmarshalCA()

	r1msg := round.temp.signRound1Message1s[j].Content().(*SignRound1Message1)
	rangeProofAliceJ, err := r1msg.UnmarshalRangeProofAlice()
	if err != nil {
		errChs <- round.WrapError(errorspkg.Wrapf(err, "UnmarshalRangeProofAlice failed"), Pj)
		return
	}

	ringPedersenBobI := round.key.GetRingPedersen(i)
	rpVs := round.key.GetAllRingPedersen()
	rpVs[i] = nil
	nu, cMu, cNuPrm, proofs, err := accmta.BobRespondsDL(
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
		// Verifier's Ring Pedersen parameters
		rpVs,
		// Bob's Ring Pedersen parameters
		ringPedersenBobI,
		// DL commitment to Bob's input b
		round.temp.bigWs[i],
	)
	round.temp.nu[j] = nu
	round.temp.cMu[i][j] = cMu
	round.temp.cNuPrm[i][j] = cNuPrm
	round.temp.proofDL[i][j] = proofs
	if err != nil {
		errChs <- round.WrapError(err, Pj)
	}
}

func (round *round2) Update() (bool, *tss.Error) {
	for i, msgArray := range round.temp.signRound2Messages {
		for j, msg := range msgArray {
			if i == j || i == round.PartyID().Index {
				continue
			}
			if round.ok[j] {
				continue
			}
			if msg == nil || !round.CanAccept(msg) {
				return false, nil
			}
		}
		round.ok[i] = true
	}
	return true, nil
}

func (round *round2) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound2Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round2) NextRound() tss.Round {
	round.started = false
	return &round3{round}
}
