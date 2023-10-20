//  Copyright (c) 2023, Circle Internet Financial, LTD.
//  All rights reserved
//  SPDX-License-Identifier: Apache-2.0
//

package cggplus

import (
	"errors"
	"math/big"
	"sync"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto/accmta"
	"github.com/bnb-chain/tss-lib/crypto/zkproofs"
	"github.com/bnb-chain/tss-lib/tss"
)

func (round *round3) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 3
	round.started = true
	round.resetOK()

	i := round.PartyID().Index

	partyCount := len(round.Parties().IDs())
	errChs := make(chan *tss.Error, partyCount*partyCount*3)
	wg := sync.WaitGroup{}

	wg.Add(1)
	go func() {
		defer wg.Done()
		round.VerifyRound2Messages(errChs)
	}()
	wg.Wait()

	for sender, _ := range round.Parties().IDs() {
		if sender == i {
			continue
		}
		wg.Add(2)
		go round.AliceEndW(sender, &wg, errChs)
		go round.AliceEndGamma(sender, &wg, errChs)
	}
	wg.Wait()
	close(errChs)
	err := round.WrapErrorChs(round.PartyID(), errChs, "Failed to process round 2 messages")
	if err != nil {
		return err
	}

	psiPrimePrime, err := round.ComputePsiPrimePrime()
	if err != nil {
		return err
	}

	HProof, err := round.ComputeHProof()
	if err != nil {
		return err
	}

	deltaProof, err := round.ComputeDeltaProof()
	if err != nil {
		return err
	}

	r3msg := NewSignRound3Message(
		round.PartyID(),
		round.temp.delta[i],
		round.temp.bigDelta[i],
		round.temp.bigH,
		psiPrimePrime,
		HProof,
		deltaProof,
	)
	round.temp.signRound3Messages[i] = r3msg
	round.out <- r3msg

	return nil
}

func (round *round3) VerifyRound2Messages(errChs chan *tss.Error) {
	i := round.PartyID().Index
	wg := sync.WaitGroup{}
	for sender, Psender := range round.Parties().IDs() {
		r2msg2 := round.temp.signRound2Message2s[sender].Content().(*SignRound2Message2)
		ec := round.Params().EC()
		pointGamma, err := r2msg2.UnmarshalGamma(ec)
		if err != nil {
			errChs <- round.WrapError(errors.New("could not UnmarshalGamma"), Psender)
			return
		}
		round.temp.pointGamma[sender] = pointGamma

		for recipient, _ := range round.Parties().IDs() {
			if sender == recipient || sender == i {
				continue
			}
			wg.Add(1)
			go func(sender, recipient int, Psender *tss.PartyID, errChs chan *tss.Error) {
				defer wg.Done()
				round.VerifyRound2Message(sender, recipient, Psender, errChs)
			}(sender, recipient, Psender, errChs)
		}
	}
	wg.Wait()
}

func (round *round3) VerifyRound2Message(sender, recipient int, Psender *tss.PartyID, errChs chan *tss.Error) {
	verifier := round.PartyID().Index
	rpVerifier := round.key.GetRingPedersen(verifier)
	ec := round.Params().EC()

	r2msg1 := round.temp.signRound2Message1s[sender][recipient].Content().(*SignRound2Message1)
	if recipient != r2msg1.UnmarshalRecipient() {
		errChs <- round.WrapError(errors.New("Could not UnmarshalRecipient"), Psender)
		return
	}
	round.temp.bigD[sender][recipient] = r2msg1.UnmarshalBigD()
	round.temp.bigF[sender][recipient] = r2msg1.UnmarshalBigF()
	round.temp.bigDHat[sender][recipient] = r2msg1.UnmarshalBigDHat()
	round.temp.bigFHat[sender][recipient] = r2msg1.UnmarshalBigFHat()

	// verify what the other recipient received
	if verifier != recipient {
		psiHat, err := r2msg1.UnmarshalPsiHat(ec)
		if err != nil {
			errChs <- round.WrapError(errors.New("UnmarshalPsiHat"), Psender)
			return
		}
		ok := accmta.AliceVerifyG(
			ec,
			round.key.PaillierPKs[recipient],
			round.key.PaillierPKs[sender],
			psiHat[verifier],
			round.temp.bigK[recipient],
			round.temp.bigDHat[sender][recipient],
			round.temp.bigFHat[sender][recipient],
			round.temp.bigWs[sender],
			rpVerifier,
		)
		if !ok {
			errChs <- round.WrapError(errors.New("bad proof"), Psender)
			return
		}

		psi, err := r2msg1.UnmarshalPsi(ec)
		if err != nil {
			errChs <- round.WrapError(errors.New("could not UnmarshalPsi"), Psender)
			return
		}
		ok = accmta.AliceVerifyG(
			ec,
			round.key.PaillierPKs[recipient],
			round.key.PaillierPKs[sender],
			psi[verifier],
			round.temp.bigK[recipient],
			round.temp.bigD[sender][recipient],
			round.temp.bigF[sender][recipient],
			round.temp.pointGamma[sender],
			rpVerifier,
		)
		if !ok {
			errChs <- round.WrapError(errors.New("bad proof"), Psender)
			return
		}
	}

	// verify for all
	r2msg2 := round.temp.signRound2Message2s[sender].Content().(*SignRound2Message2)
	psiPrime, err := r2msg2.UnmarshalPsiPrime(ec)
	if err != nil {
		errChs <- round.WrapError(errors.New("could not UnmarshalPsiPrime"), Psender)
		return
	}
	statement := &zkproofs.LogStarStatement{
		Ell: zkproofs.GetEll(ec),
		N0:  round.key.PaillierPKs[sender].N,
		C:   round.temp.bigG[sender],
		X:   round.temp.pointGamma[sender],
	}
	ok := psiPrime[verifier].Verify(statement, rpVerifier)
	if !ok {
		errChs <- round.WrapError(errors.New("bad proof"), Psender)
		return
	}
}

func (round *round3) AliceEndW(sender int, wg *sync.WaitGroup, errChs chan *tss.Error) {
	defer wg.Done()
	i := round.PartyID().Index
	rp := round.key.GetRingPedersen(i)
	ec := round.Params().EC()
	Psender := round.Parties().IDs()[sender]

	r2msg1 := round.temp.signRound2Message1s[sender][i].Content().(*SignRound2Message1)
	if i != r2msg1.UnmarshalRecipient() {
		errChs <- round.WrapError(errors.New("could not parse message"), Psender)
		return
	}
	round.temp.bigDHat[sender][i] = r2msg1.UnmarshalBigDHat()
	round.temp.bigFHat[sender][i] = r2msg1.UnmarshalBigFHat()
	psiHat, err := r2msg1.UnmarshalPsiHat(ec)
	if err != nil {
		errChs <- round.WrapError(errors.New("could not UnmarshalPsiHat"), Psender)
		return
	}

	alphaHat, err := accmta.AliceEndG(
		ec,
		round.key.PaillierSK,
		round.key.PaillierPKs[sender],
		psiHat[i],
		round.temp.bigK[i],
		round.temp.bigDHat[sender][i],
		round.temp.bigFHat[sender][i],
		round.temp.bigWs[sender],
		rp,
	)
	if err != nil {
		errChs <- round.WrapError(errors.New("Could not compute AliceEndW"), Psender)
		return
	}
	round.temp.alphaHat[sender] = alphaHat
}

func (round *round3) AliceEndGamma(sender int, wg *sync.WaitGroup, errChs chan *tss.Error) {
	defer wg.Done()
	i := round.PartyID().Index
	rp := round.key.GetRingPedersen(i)
	ec := round.Params().EC()
	Psender := round.Parties().IDs()[sender]

	r2msg1 := round.temp.signRound2Message1s[sender][i].Content().(*SignRound2Message1)
	if i != r2msg1.UnmarshalRecipient() {
		errChs <- round.WrapError(errors.New("could not parse signRound2Message1s"), Psender)
		return
	}
	round.temp.bigD[sender][i] = r2msg1.UnmarshalBigD()
	round.temp.bigF[sender][i] = r2msg1.UnmarshalBigF()

	psi, err := r2msg1.UnmarshalPsi(ec)
	if err != nil {
		errChs <- round.WrapError(errors.New("could not UnmarshalPsi"), Psender)
		return
	}
	r2msg2 := round.temp.signRound2Message2s[sender].Content().(*SignRound2Message2)
	pointGamma, err := r2msg2.UnmarshalGamma(ec)
	if err != nil {
		errChs <- round.WrapError(errors.New("could not UnmarshalGamma"), Psender)
		return
	}
	round.temp.pointGamma[sender] = pointGamma

	alphaIj, err := accmta.AliceEndG(
		ec,
		round.key.PaillierSK,
		round.key.PaillierPKs[sender],
		psi[i],
		round.temp.bigK[i],
		round.temp.bigD[sender][i],
		round.temp.bigF[sender][i],
		round.temp.pointGamma[sender],
		rp,
	)
	if err != nil {
		errChs <- round.WrapError(errors.New("Could not compute response AliceEndGamma"), Psender)
		return
	}
	round.temp.alpha[sender] = alphaIj
}

func (round *round3) ComputeGamma() {
	Gamma := round.temp.pointGamma[0]
	for j := range round.Parties().IDs() {
		if j == 0 {
			continue
		}
		Gamma, _ = Gamma.Add(round.temp.pointGamma[j])
	}
	i := round.PartyID().Index
	round.temp.Gamma = Gamma
	round.temp.bigDelta[i] = Gamma.ScalarMult(round.temp.k)
}

func (round *round3) ComputeDelta() {
	i := round.PartyID().Index
	modQ := common.ModInt(round.Params().EC().Params().N)
	delta := modQ.Mul(round.temp.k, round.temp.gamma)
	for j := range round.Parties().IDs() {
		if j == round.PartyID().Index {
			continue
		}
		temp := modQ.Add(round.temp.alpha[j], round.temp.beta[j])
		delta = modQ.Add(delta, temp)
	}
	round.temp.delta[i] = delta
}

func (round *round3) ComputeChi() {
	i := round.PartyID().Index
	modQ := common.ModInt(round.Params().EC().Params().N)
	chi := modQ.Mul(round.temp.k, round.temp.w)
	for j := range round.Parties().IDs() {
		if j == i {
			continue
		}
		temp := modQ.Add(round.temp.alphaHat[j], round.temp.betaHat[j])
		chi = modQ.Add(chi, temp)
	}
	round.temp.chi = chi
}

func (round *round3) ComputePsiPrimePrime() ([]*zkproofs.LogStarProof, *tss.Error) {
	round.ComputeDelta()
	round.ComputeChi()
	round.ComputeGamma()
	i := round.PartyID().Index
	Pi := round.Parties().IDs()[i]
	ec := round.Params().EC()

	ski := round.key.PaillierSK
	_, rho, errd := ski.DecryptFull(round.temp.bigK[i])
	if errd != nil {
		return nil, round.WrapError(errors.New("could not decrypt bigK"), Pi)
	}

	statement := &zkproofs.LogStarStatement{
		Ell: zkproofs.GetEll(ec),
		N0:  round.key.PaillierSK.PublicKey.N,
		C:   round.temp.bigK[i],
		X:   round.temp.bigDelta[i],
		G:   round.temp.Gamma,
	}
	witness := &zkproofs.LogStarWitness{
		X:   round.temp.k,
		Rho: rho,
	}
	rpVs := round.key.GetAllRingPedersen()
	rpVs[i] = nil
	psiPrimePrime := make([]*zkproofs.LogStarProof, len(rpVs))
	wg := sync.WaitGroup{}
	for j, rp := range rpVs {
		if j == i {
			continue
		}
		wg.Add(1)
		go func(j int, rp *zkproofs.RingPedersenParams) {
			defer wg.Done()
			psiPrimePrime[j] = zkproofs.NewLogStarProof(witness, statement, rp)
		}(j, rp)
	}
	wg.Wait()
	return psiPrimePrime, nil
}

func (round *round3) ComputeHProof() (*zkproofs.MulProof, *tss.Error) {
	i := round.PartyID().Index
	Pi := round.Parties().IDs()[i]
	pki := round.key.PaillierPKs[i]
	bigH, rho, err := pki.HomoMultAndReturnRandomness(round.temp.gamma, round.temp.bigK[i])
	if err != nil {
		return nil, round.WrapError(errors.New("trouble computing bigH"), Pi)
	}
	round.temp.bigH = bigH
	x, rhox, err := round.key.PaillierSK.DecryptFull(round.temp.bigG[i])
	if err != nil || x.Cmp(round.temp.gamma) != 0 {
		return nil, round.WrapError(errors.New("Bad G[i]"), Pi)
	}

	witness := &zkproofs.MulWitness{
		X:    round.temp.gamma,
		Rho:  rho,
		Rhox: rhox,
	}
	statement := &zkproofs.MulStatement{
		N: round.key.PaillierPKs[i].N,
		X: round.temp.bigG[i],
		Y: round.temp.bigK[i],
		C: round.temp.bigH,
	}
	Hproof := zkproofs.NewMulProof(witness, statement)
	return Hproof, nil
}

func (round *round3) ComputeXDelta() (*big.Int, error) {
	i := round.PartyID().Index
	ski := round.key.PaillierSK
	var err error
	XDelta := round.temp.bigH
	for j := range round.Parties().IDs() {
		if j == i {
			continue
		}
		XDelta, err = ski.PublicKey.HomoAdd(XDelta, round.temp.bigD[j][i])
		if err != nil {
			return nil, errors.New("could not compute XDelta")
		}
		XDelta, err = ski.PublicKey.HomoAdd(XDelta, round.temp.bigF[i][j])
		if err != nil {
			return nil, errors.New("could not compute XDelta")
		}
	}
	return XDelta, nil
}

func (round *round3) ComputeDeltaProof() ([]*zkproofs.DecProof, *tss.Error) {
	XDelta, err := round.ComputeXDelta()
	if err != nil {
		return nil, round.WrapError(err)
	}
	i := round.PartyID().Index
	Pi := round.Parties().IDs()[i]
	ski := round.key.PaillierSK
	q := round.Params().EC().Params().N

	d, rho, err := ski.DecryptFull(XDelta)
	if err != nil {
		return nil, round.WrapError(errors.New("could not decrypt XDelta"), Pi)
	}

	modQ := common.ModInt(q)
	if !modQ.IsCongruent(d, round.temp.delta[i]) {
		return nil, round.WrapError(errors.New("badly formed XDelta"), Pi)
	}

	statement := &zkproofs.DecStatement{
		Q:   q,
		Ell: zkproofs.GetEll(round.Params().EC()),
		N0:  ski.PublicKey.N,
		C:   XDelta,
		X:   round.temp.delta[i],
	}
	witness := &zkproofs.DecWitness{
		Y:   d,
		Rho: rho,
	}
	rpVs := round.key.GetAllRingPedersen()
	rpVs[i] = nil
	proofs := make([]*zkproofs.DecProof, len(rpVs))
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
	return proofs, nil
}

func (round *round3) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.signRound3Messages {
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

func (round *round3) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound3Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round3) NextRound() tss.Round {
	round.started = false
	return &round4{round}
}
