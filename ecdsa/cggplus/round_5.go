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

package cggplus

import (
	"errors"
	"math/big"
	"sync"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto/zkproofs"
	"github.com/bnb-chain/tss-lib/tss"
)

func (round *round5) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 5
	round.started = true
	round.resetOK()

	// The check that temp.m = hash(msg) is in Zq is delayed to round 5 to allow
	// presigning bulk computation of rounds 1-4.
	if round.temp.m.Cmp(round.Params().EC().Params().N) >= 0 {
		return round.WrapError(errors.New("hashed message is not valid"))
	}

	bigHHat, bigHHatProof, sigmaProof, err := round.ComputeVals()
	if err != nil {
		return err
	}

	r5msg := NewSignRound5Message(
		round.PartyID(),
		round.temp.sigma, bigHHat,
		bigHHatProof, sigmaProof)
	round.temp.signRound5Messages[round.PartyID().Index] = r5msg
	round.out <- r5msg

	round.CleanUpRound5Data()
	return nil
}

func (round *round5) ComputeVals() (bigHHat *big.Int, bigHHatProof []*zkproofs.MulStarProof, sigmaProof []*zkproofs.DecProof, terr *tss.Error) {
	i := round.PartyID().Index
	pki := round.key.PaillierPKs[i]
	modQ := common.ModInt(round.Params().EC().Params().N)
	bigHHatProof = make([]*zkproofs.MulStarProof, len(round.Parties().IDs()))
	sigmaProof = make([]*zkproofs.DecProof, len(round.Parties().IDs()))

	bigHHat, rho, err := pki.HomoMultAndReturnRandomness(round.temp.w, round.temp.bigK[i])
	if err != nil {
		terr = round.WrapError(errors.New("could not compute bigHHat"))
	}
	witnessBigHHat := &zkproofs.MulStarWitness{
		X:   round.temp.w,
		Rho: rho,
	}
	statementBigHHat := &zkproofs.MulStarStatement{
		Ell: zkproofs.GetEll(round.Params().EC()),
		N0:  pki.N,
		C:   round.temp.bigK[i],
		D:   bigHHat,
		X:   round.temp.bigWs[i],
	}

	sigma := modQ.Add(modQ.Mul(round.temp.m, round.temp.k), modQ.Mul(round.temp.rx, round.temp.chi))
	prod := bigHHat
	for j := range round.Parties().IDs() {
		if j == i {
			continue
		}
		temp, err := round.key.PaillierPKs[i].HomoAdd(round.temp.bigDHat[j][i], round.temp.bigFHat[i][j])
		if err != nil {
			terr = round.WrapError(errors.New("could not compute bigSigma"))
			return
		}
		prod, err = round.key.PaillierPKs[i].HomoAdd(prod, temp)
		if err != nil {
			terr = round.WrapError(errors.New("could not compute bigSigma"))
			return
		}
	}
	prod, err = pki.HomoMult(round.temp.rx, prod)
	if err != nil {
		terr = round.WrapError(errors.New("could not compute bigSigma"))
		return
	}
	prodPrime, err := pki.HomoMult(round.temp.m, round.temp.bigK[i])
	if err != nil {
		terr = round.WrapError(errors.New("could not compute bigSigma"))
		return
	}
	bigSigma, err := pki.HomoAdd(prod, prodPrime)
	if err != nil {
		terr = round.WrapError(errors.New("could not compute bigSigma"))
		return
	}
	littleSigma, rhoSigma, err := round.key.PaillierSK.DecryptFull(bigSigma)
	if err != nil {
		terr = round.WrapError(errors.New("could not compute bigSigma"))
	}
	if !modQ.IsCongruent(sigma, littleSigma) {
		terr = round.WrapError(errors.New("could not compute bigSigma"))
		return
	}
	witnessSigma := &zkproofs.DecWitness{
		Y:   littleSigma,
		Rho: rhoSigma,
	}
	statementSigma := &zkproofs.DecStatement{
		Q:   round.Params().EC().Params().N,
		Ell: zkproofs.GetEll(round.Params().EC()),
		N0:  pki.N,
		C:   bigSigma,
		X:   sigma,
	}

	wg := sync.WaitGroup{}
	rpVs := round.key.GetAllRingPedersen()
	rpVs[i] = nil
	for j, rp := range rpVs {
		if j == i {
			continue
		}
		wg.Add(2)
		go func(j int, rp *zkproofs.RingPedersenParams) {
			defer wg.Done()
			bigHHatProof[j] = zkproofs.NewMulStarProof(witnessBigHHat, statementBigHHat, rp)
		}(j, rp)
		go func(j int, rp *zkproofs.RingPedersenParams) {
			defer wg.Done()
			sigmaProof[j] = zkproofs.NewDecProof(witnessSigma, statementSigma, rp)
		}(j, rp)
	}
	wg.Wait()
	round.temp.sigma = sigma
	return
}

func (round *round5) CleanUpRound5Data() {
	round.temp.w = nil
	round.temp.k = nil
	round.temp.chi = nil
}

func (round *round5) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.signRound5Messages {
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

func (round *round5) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound5Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round5) NextRound() tss.Round {
	round.started = false
	return &finalization{round}
}
