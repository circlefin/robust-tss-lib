// Copyright 2023 Circle

package cggplus

import (
	"errors"
	"fmt"
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
	for sender, _ := range round.Parties().IDs() {
		if sender == i {
			continue
		}
		wg.Add(2)
		go round.AliceEndW(sender, &wg, errChs)
		go round.AliceEndGamma(sender, &wg, errChs)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		round.VerifyRound2Messages(errChs)
	}()
	wg.Wait()
	close(errChs)
	err := round.WrapErrorChs(round.PartyID(), errChs, "Failed to process round 2 messages")
	if err != nil {
		return err
	}

	psiPrimePrime, err := round.ComputeProofs()
	if err != nil {
		return err
	}

	r3msg := NewSignRound3Message(
		round.PartyID(),
		round.temp.delta[i],
		round.temp.bigDelta[i],
		psiPrimePrime,
	)
	round.temp.signRound3Messages[i] = r3msg
	round.out <- r3msg

	return nil
}

func (round *round3) VerifyRound2Messages(errChs chan *tss.Error) {
	i := round.PartyID().Index
	wg := sync.WaitGroup{}
	for sender, _ := range round.Parties().IDs() {
		for recipient, _ := range round.Parties().IDs() {
			if sender == recipient || sender == i {
				continue
			}
			wg.Add(1)
			go func(sender, recipient int, errChs chan *tss.Error) {
				defer wg.Done()
				round.VerifyRound2Message(sender, recipient, errChs)
			}(sender, recipient, errChs)
		}
	}
	wg.Wait()
}

func (round *round3) VerifyRound2Message(sender, recipient int, errChs chan *tss.Error) {
	verifier := round.PartyID().Index
	rpVerifier := round.key.GetRingPedersen(verifier)
	ec := round.Params().EC()

	r2msg1 := round.temp.signRound2Message1s[sender][recipient].Content().(*SignRound2Message1)
	if recipient != r2msg1.UnmarshalRecipient() {
		errChs <- round.WrapError(fmt.Errorf("improper message [%d][%d]", sender, recipient))
		return
	}
	round.temp.bigD[sender][recipient] = r2msg1.UnmarshalBigD()
	round.temp.bigF[sender][recipient] = r2msg1.UnmarshalBigF()
	round.temp.bigDHat[sender][recipient] = r2msg1.UnmarshalBigDHat()
	round.temp.bigFHat[sender][recipient] = r2msg1.UnmarshalBigFHat()

	r2msg2 := round.temp.signRound2Message2s[sender].Content().(*SignRound2Message2)
	pointGamma, err := r2msg2.UnmarshalGamma(ec)
	if err != nil {
		errChs <- round.WrapError(fmt.Errorf("could not parse Gamma [%d][%d]", sender, verifier))
		return
	}
	round.temp.pointGamma[sender] = pointGamma

	// verify what the other recipient received
	if verifier != recipient {
		psiHat, err := r2msg1.UnmarshalPsiHat(ec)
		if err != nil {
			errChs <- round.WrapError(fmt.Errorf("could not parse proof psiHat [%d][%d]", sender, recipient))
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
			errChs <- round.WrapError(fmt.Errorf("proof psiHat failed to verify [%d][%d][%d]", sender, recipient, verifier))
			return
		}

		psi, err := r2msg1.UnmarshalPsi(ec)
		if err != nil {
			errChs <- round.WrapError(fmt.Errorf("could not parse proof psi [%d][%d]", sender, recipient))
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
			errChs <- round.WrapError(fmt.Errorf("proof psi failed to verify [%d][%d][%d]", sender, recipient, verifier))
			return
		}
	}

	// verify for all
	psiPrime, err := r2msg2.UnmarshalPsiPrime(ec)
	if err != nil {
		errChs <- round.WrapError(fmt.Errorf("could not parse proof psiPrime [%d][%d]", sender, recipient))
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
		errChs <- round.WrapError(fmt.Errorf("proof psiPrime failed to verify [%d][%d]", sender, verifier))
		return
	}
}

func (round *round3) AliceEndW(sender int, wg *sync.WaitGroup, errChs chan *tss.Error) {
	defer wg.Done()
	i := round.PartyID().Index
	rp := round.key.GetRingPedersen(i)
	ec := round.Params().EC()

	r2msg1 := round.temp.signRound2Message1s[sender][i].Content().(*SignRound2Message1)
	if i != r2msg1.UnmarshalRecipient() {
		errChs <- round.WrapError(fmt.Errorf("improper message [%d][%d]", sender, i))
		return
	}
	round.temp.bigDHat[sender][i] = r2msg1.UnmarshalBigDHat()
	round.temp.bigFHat[sender][i] = r2msg1.UnmarshalBigFHat()
	psiHat, err := r2msg1.UnmarshalPsiHat(ec)
	if err != nil {
		errChs <- round.WrapError(fmt.Errorf("could not parse proof psiHat [%d][%d]", sender, i))
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
		errChs <- round.WrapError(fmt.Errorf("AliceEndW failed to verify [%d][%d]", sender, i))
		round.temp.alpha[sender] = big.NewInt(1)
		return
	}
	round.temp.alphaHat[sender] = alphaHat
}

func (round *round3) AliceEndGamma(sender int, wg *sync.WaitGroup, errChs chan *tss.Error) {
	defer wg.Done()
	i := round.PartyID().Index
	rp := round.key.GetRingPedersen(i)
	ec := round.Params().EC()

	r2msg1 := round.temp.signRound2Message1s[sender][i].Content().(*SignRound2Message1)
	if i != r2msg1.UnmarshalRecipient() {
		errChs <- round.WrapError(fmt.Errorf("improper message [%d][%d]", sender, i))
		return
	}
	round.temp.bigD[sender][i] = r2msg1.UnmarshalBigD()
	round.temp.bigF[sender][i] = r2msg1.UnmarshalBigF()
	psi, err := r2msg1.UnmarshalPsi(ec)
	if err != nil {
		errChs <- round.WrapError(fmt.Errorf("could not parse proof psi [%d][%d]", sender, i))
		return
	}
	r2msg2 := round.temp.signRound2Message2s[sender].Content().(*SignRound2Message2)
	pointGamma, err := r2msg2.UnmarshalGamma(ec)
	if err != nil {
		errChs <- round.WrapError(fmt.Errorf("could not parse Gamma [%d]", sender))
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
		errChs <- round.WrapError(fmt.Errorf("AliceEndGamma failed to verify [%d][%d]", sender, i))
		round.temp.alpha[sender] = big.NewInt(1)
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
		temp := modQ.Add(round.temp.alpha[j], round.temp.beta[i][j])
		delta = modQ.Add(delta, temp)
	}
	round.temp.delta[i] = delta
}

func (round *round3) ComputeChi() {
	i := round.PartyID().Index
	modQ := common.ModInt(round.Params().EC().Params().N)
	chi := modQ.Mul(round.temp.k, round.temp.w)
	for j := range round.Parties().IDs() {
		if j == round.PartyID().Index {
			continue
		}
		temp := modQ.Add(round.temp.alphaHat[j], round.temp.betaHat[i][j])
		chi = modQ.Add(chi, temp)
	}
	round.temp.chi[i] = chi
}

func (round *round3) ComputeProofs() ([]*zkproofs.LogStarProof, *tss.Error) {
	round.ComputeDelta()
	round.ComputeChi()
	round.ComputeGamma()
	i := round.PartyID().Index
	ec := round.Params().EC()

	ski := round.key.PaillierSK
	_, rho, errd := ski.DecryptFull(round.temp.bigK[i])
	if errd != nil {
		return nil, round.WrapError(fmt.Errorf("could not decrypt D"))
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
