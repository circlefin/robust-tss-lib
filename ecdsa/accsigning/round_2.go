// Copyright (c) 2023, Circle Internet Financial, LTD. All rights reserved.
//
//  SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package accsigning

import (
	"errors"
	"fmt"
	"sync"

	"github.com/bnb-chain/tss-lib/crypto/accmta"
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

	partyCount := len(round.Parties().IDs())
	proofP := Make2DSlice[*zkproofs.AffPProof](partyCount)
	proofDL := Make2DSlice[*zkproofs.AffGProof](partyCount)
	proofBeta := Make2DSlice[*zkproofs.DecProof](partyCount)
	proofNu := Make2DSlice[*zkproofs.DecProof](partyCount)

	errChs := make(chan *tss.Error, (len(round.Parties().IDs())-1)*3)
	wg := sync.WaitGroup{}
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}

		wg.Add(2)
		go round.BobRespondsP(j, Pj, proofP, proofBeta, &wg, errChs)
		go round.BobRespondsDL(j, Pj, proofDL, proofNu, &wg, errChs)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		round.VerifyRound1Messages(errChs)
	}()
	wg.Wait()
	close(errChs)
	err := round.WrapErrorChs(round.PartyID(), errChs, "Failed to verify round 4 messages")
	if err != nil {
		return err
	}

	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}

		r2msg := NewSignRound2Message(
			Pj, round.PartyID(),
			round.temp.cAlpha[i][j],
			round.temp.cBeta[i][j],
			round.temp.cBetaPrm[i][j],
			round.temp.cMu[i][j],
			round.temp.cNu[i][j],
			round.temp.cNuPrm[i][j],
			proofP[j], proofDL[j],
			proofBeta[j], proofNu[j])
		round.out <- r2msg
	}
	return nil
}

func (round *round2) VerifyRound1Messages(errChs chan *tss.Error) {
	wg := sync.WaitGroup{}
	i := round.PartyID().Index
	for j, Pj := range round.Parties().IDs() {
		if i == j {
			continue
		}
		wg.Add(1)
		go func(j int, Pj *tss.PartyID) {
			defer wg.Done()
			round.VerifyRound1Message(j, Pj, errChs)
		}(j, Pj)
	}
	wg.Wait()
}

func (round *round2) VerifyRound1Message(j int, Pj *tss.PartyID, errChs chan *tss.Error) {
	i := round.PartyID().Index

	r1msg1 := round.temp.signRound1Message1s[j].Content().(*SignRound1Message1)
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
	round.temp.Xkw[j] = r1msg2.UnmarshalXKw()
	rp := round.key.GetRingPedersen(i)

	paillierPK := round.key.PaillierPKs[j]
	bigW := round.temp.bigWs[j]
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
		D:   round.temp.Xkw[j],
		X:   bigW,
	}

	if !proofXgamma.Verify(statementXgamma, rp) ||
		!proofXkgamma.Verify(statementXkgamma) ||
		!proofXkw.Verify(statementXkw, rp) {
		errChs <- round.WrapError(fmt.Errorf("Failed to verify proofs from [%d]", j))
		return
	}
	return
}

func (round *round2) BobRespondsP(j int, Pj *tss.PartyID, proofP [][]*zkproofs.AffPProof, proofBeta [][]*zkproofs.DecProof, wg *sync.WaitGroup, errChs chan *tss.Error) {
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
		errChs <- round.WrapError(fmt.Errorf("UnmarshalRangeProofAlice failed."), Pj)
		return
	}

	ringPedersenBobI := round.key.GetRingPedersen(i)
	rpVs := round.key.GetAllRingPedersen()
	rpVs[i] = nil
	beta, cAlpha, cBeta, cBetaPrm, proofs, decProofs, err := accmta.BobRespondsP(
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
	if err != nil {
		errChs <- round.WrapError(err, Pj)
	}

	// should be thread safe as these are pre-allocated
	round.temp.beta[j] = beta
	round.temp.cAlpha[i][j] = cAlpha
	round.temp.cBeta[i][j] = cBeta
	round.temp.cBetaPrm[i][j] = cBetaPrm
	proofP[j] = proofs
	proofBeta[j] = decProofs
}

// BobRespondsDL on share k*w, Bob's secret is w
func (round *round2) BobRespondsDL(j int, Pj *tss.PartyID, proofDL [][]*zkproofs.AffGProof, proofNu [][]*zkproofs.DecProof, wg *sync.WaitGroup, errChs chan *tss.Error) {
	defer wg.Done()
	i := round.PartyID().Index
	r2msg := round.temp.signRound1Message2s[j].Content().(*SignRound1Message2)
	cA := r2msg.UnmarshalCA()

	r1msg := round.temp.signRound1Message1s[j].Content().(*SignRound1Message1)
	rangeProofAliceJ, err := r1msg.UnmarshalRangeProofAlice()
	if err != nil {
		errChs <- round.WrapError(fmt.Errorf("UnmarshalRangeProofAlice failed"), Pj)
		return
	}

	ringPedersenBobI := round.key.GetRingPedersen(i)
	rpVs := round.key.GetAllRingPedersen()
	rpVs[i] = nil
	nu, cMu, cNu, cNuPrm, proofs, decProofs, err := accmta.BobRespondsDL(
		round.Params().EC(),
		// Alice's public key
		round.key.PaillierPKs[j],
		// Bob's public key
		round.key.PaillierSK,
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
	if err != nil {
		errChs <- round.WrapError(err, Pj)
	}

	round.temp.nu[j] = nu
	round.temp.cMu[i][j] = cMu
	round.temp.cNu[i][j] = cNu
	round.temp.cNuPrm[i][j] = cNuPrm
	proofDL[j] = proofs
	proofNu[j] = decProofs
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
