//  Copyright (c) 2023, Circle Internet Financial, LTD.
//  All rights reserved
//  SPDX-License-Identifier: Apache-2.0
//

package accsigning

import (
	"errors"
	"fmt"
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

	err := round.VerifyRound4Messages()
	if err != nil {
		return err
	}

	err = round.ComputeR()
	if err != nil {
		return err
	}

	err = round.ComputeSi()
	if err != nil {
		return err
	}

	proofs, err := round.ComputeProofs()
	if err != nil {
		return err
	}
	r5msg := NewSignRound5Message(round.PartyID(), round.temp.si, proofs)
	round.temp.signRound5Messages[round.PartyID().Index] = r5msg
	round.out <- r5msg

	round.temp.CleanUpPreSigningData()
	return nil
}

func (round *round5) VerifyRound4Messages() *tss.Error {
	errChs := make(chan *tss.Error, len(round.Parties().IDs()))
	wg := sync.WaitGroup{}
	i := round.PartyID().Index
	rp := round.key.GetRingPedersen(i)
	for j, _ := range round.Parties().IDs() {
		if i == j {
			continue
		}

		wg.Add(1)
		go func(sender int, errChs chan *tss.Error) {
			defer wg.Done()
			r4msg := round.temp.signRound4Messages[sender].Content().(*SignRound4Message)
			proof, err := r4msg.UnmarshalProof(round.Params().EC())
			if err != nil {
				errChs <- round.WrapError(errors.New(fmt.Sprintf("failed to parse proof from party %d.", sender)))
			}
			Gamma, err := r4msg.UnmarshalGamma(round.Params().EC())
			round.temp.pointGamma[sender] = Gamma
			if err != nil {
				errChs <- round.WrapError(errors.New(fmt.Sprintf("failed to parse Gamma from party %d.", sender)))
			}
			pkj := round.key.PaillierPKs[sender]
			statement := &zkproofs.LogStarStatement{
				Ell: zkproofs.GetEll(round.Params().EC()),
				N0:  pkj.N,
				C:   round.temp.Xgamma[sender],
				X:   round.temp.pointGamma[sender],
			}
			if !proof[i].Verify(statement, rp) {
				errChs <- round.WrapError(errors.New(fmt.Sprintf("failed to parse Gamma from party %d.", sender)))
			}
		}(j, errChs)
	}
	wg.Wait()
	close(errChs)
	err := round.WrapErrorChs(round.PartyID(), errChs, "Failed to verify round 4 messages")
	if err != nil {
		return err
	}

	return nil
}

func (round *round5) ComputeR() *tss.Error {
	i := round.PartyID().Index
	bigR := round.temp.pointGamma[i]
	if bigR == nil {
		return round.WrapError(errors.New("Gamma[i] is nil."))
	}
	var err error
	for j := range round.Parties().IDs() {
		if i == j {
			continue
		}
		if round.temp.pointGamma[j] == nil {
			return round.WrapError(errors.New("Gamma [j] is nil"))
		}
		bigR, err = bigR.Add(round.temp.pointGamma[j])
		if err != nil {
			return round.WrapError(errors.New("Cannot compute R from pointGammas."))
		}
	}
	round.temp.bigR = bigR.ScalarMult(round.temp.finalDeltaInv)
	round.temp.rx = round.temp.bigR.X()
	round.temp.ry = round.temp.bigR.Y()
	return nil
}

func (round *round5) ComputeSi() (err *tss.Error) {
	modQ := common.ModInt(round.Params().EC().Params().N)
	wg := sync.WaitGroup{}
	err = nil

	for i := range round.Parties().IDs() {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			Psi := round.temp.Xkw[i]
			pki := round.key.PaillierPKs[i]
			modN2 := common.ModInt(pki.NSquare())
			for j := range round.Parties().IDs() {
				if j == i {
					continue
				}
				Psi = modN2.Mul(Psi, round.temp.cMu[j][i]) // encrypted under pki
				Psi = modN2.Mul(Psi, round.temp.cNu[i][j]) // encrypted under pki
			}
			S := zkproofs.PseudoPaillierEncrypt(
				round.temp.cA[i],
				round.temp.m,
				Psi,
				new(big.Int).Mul(round.temp.rx, round.temp.m),
				pki.NSquare(),
			)
			round.temp.bigS[i] = S
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		sigma := modQ.Mul(round.temp.k, round.temp.w)
		for j := range round.Parties().IDs() {
			if j == round.PartyID().Index {
				continue
			}
			temp := modQ.Add(round.temp.mu[j], round.temp.nu[j])
			sigma = modQ.Add(sigma, temp)
		}
		round.temp.sigma = sigma
	}()
	wg.Wait()
	if err != nil {
		return err
	}
	round.temp.si = modQ.Add(modQ.Mul(round.temp.m, round.temp.k), modQ.Mul(round.temp.rx, round.temp.sigma))
	return nil
}

func (round *round5) ComputeProofs() (proofs []*zkproofs.DecProof, err *tss.Error) {
	i := round.PartyID().Index
	ski := round.key.PaillierSK
	statement := &zkproofs.DecStatement{
		Q:   round.Params().EC().Params().N,
		Ell: zkproofs.GetEll(round.Params().EC()),
		N0:  ski.PublicKey.N,
		C:   round.temp.bigS[i],
		X:   round.temp.si,
	}
	y, rho, errd := ski.DecryptFull(round.temp.bigS[i])
	if errd != nil {
		return nil, round.WrapError(fmt.Errorf("could not decrypt D"))
	}
	witness := &zkproofs.DecWitness{
		Y:   y,
		Rho: rho,
	}
	rpVs := round.key.GetAllRingPedersen()
	rpVs[i] = nil
	proofs = make([]*zkproofs.DecProof, len(rpVs))
	wg := sync.WaitGroup{}
	for j, rp := range rpVs {
		if j == i {
			continue
		}
		wg.Add(1)
		go func(j int, rp *zkproofs.RingPedersenParams) {
			defer wg.Done()
			proofs[j] = zkproofs.NewDecProof(witness, statement, rp)
		}(j, rp)
	}
	wg.Wait()

	for j, pf := range proofs {
		if j != i && pf.IsNil() {
			return proofs, round.WrapError(errors.New("Failed to create one or more proofs."))
		}
	}
	return proofs, nil
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
