//  Copyright (c) 2023, Circle Internet Financial, LTD.
//  All rights reserved
//

package accsigning

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
		go round.AliceEndP(sender, &wg, errChs)
		go round.AliceEndDL(sender, &wg, errChs)
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

	d, proofs, err := round.ComputeProofs()
	if err != nil {
		return err
	}

	r3msg := NewSignRound3Message(
		round.PartyID(),
		round.temp.delta[i],
		d,
		proofs,
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

	r2msg := round.temp.signRound2Messages[sender][recipient].Content().(*SignRound2Message)
	if recipient != r2msg.UnmarshalRecipient() {
		errChs <- round.WrapError(fmt.Errorf("improper message [%d][%d]", sender, recipient))
		return
	}

	proofPs, err := r2msg.UnmarshalProofP()
	if err != nil || len(proofPs) <= verifier {
		errChs <- round.WrapError(fmt.Errorf("error getting proofP [%d][%d]", sender, recipient))
		return
	}
	proofP := proofPs[verifier]

	round.temp.cAlpha[sender][recipient] = r2msg.UnmarshalCAlpha()
	round.temp.cBetaPrm[sender][recipient] = r2msg.UnmarshalCBetaPrm()
	ok := accmta.AliceVerifyP(
		round.Params().EC(),
		round.key.PaillierPKs[recipient],
		round.key.PaillierPKs[sender],
		proofP,
		round.temp.cA[recipient],
		round.temp.cAlpha[sender][recipient],
		round.temp.cBetaPrm[sender][recipient],
		round.temp.Xgamma[sender],
		round.key.GetRingPedersen(verifier),
	)
	if !ok {
		errChs <- round.WrapError(fmt.Errorf("failed to verify proofP [%d][%d][%d]", sender, recipient, verifier))
		return
	}

	round.temp.cBeta[sender][recipient] = r2msg.UnmarshalCBeta()
	proofBeta, err := r2msg.UnmarshalProofBeta(round.Params().EC())
	if err != nil {
		errChs <- round.WrapError(fmt.Errorf("failed to parse proofBeta [%d][%d][%d]", sender, recipient, verifier))
		return
	}
	ok = accmta.DecProofVerify(
		round.key.PaillierPKs[sender],
		round.Params().EC(),
		proofBeta[verifier],
		round.temp.cBeta[sender][recipient],
		round.temp.cBetaPrm[sender][recipient],
		round.key.GetRingPedersen(verifier),
	)
	if !ok {
		errChs <- round.WrapError(fmt.Errorf("failed to verify proofBeta [%d][%d][%d]", sender, recipient, verifier))
		return
	}

	proofDLs, err := r2msg.UnmarshalProofDL(round.Params().EC())
	if err != nil || len(proofDLs) <= verifier {
		errChs <- round.WrapError(fmt.Errorf("error getting proofDL [%d][%d]", sender, recipient))
		return
	}
	proofDL := proofDLs[verifier]

	round.temp.cMu[sender][recipient] = r2msg.UnmarshalCMu()
	round.temp.cNuPrm[sender][recipient] = r2msg.UnmarshalCNuPrm()
	ok = accmta.AliceVerifyDL(
		round.Params().EC(),
		round.key.PaillierPKs[recipient],
		round.key.PaillierPKs[sender],
		proofDL,
		round.temp.cA[recipient],
		round.temp.cMu[sender][recipient],
		round.temp.cNuPrm[sender][recipient],
		round.temp.bigWs[sender],
		round.key.GetRingPedersen(verifier),
	)
	if !ok {
		errChs <- round.WrapError(fmt.Errorf("failed to verify proofDL [%d][%d][%d]", sender, recipient, verifier))
		return
	}

	round.temp.cNu[sender][recipient] = r2msg.UnmarshalCNu()
	proofNu, err := r2msg.UnmarshalProofNu(round.Params().EC())
	if err != nil {
		errChs <- round.WrapError(fmt.Errorf("failed to parse proofNu [%d][%d][%d]", sender, recipient, verifier))
		return
	}
	ok = accmta.DecProofVerify(
		round.key.PaillierPKs[sender],
		round.Params().EC(),
		proofNu[verifier],
		round.temp.cNu[sender][recipient],
		round.temp.cNuPrm[sender][recipient],
		round.key.GetRingPedersen(verifier),
	)
	if !ok {
		errChs <- round.WrapError(fmt.Errorf("failed to verify proofNu [%d][%d][%d]", sender, recipient, verifier))
		return
	}

}

func (round *round3) AliceEndP(sender int, wg *sync.WaitGroup, errChs chan *tss.Error) {
	defer wg.Done()
	i := round.PartyID().Index
	r2msg := round.temp.signRound2Messages[sender][i].Content().(*SignRound2Message)
	proofPs, err := r2msg.UnmarshalProofP()
	if err != nil || len(proofPs) <= i {
		errChs <- round.WrapError(fmt.Errorf("error parsing proofP [%d][%d] %v len %d\n", sender, i, err, len(proofPs)))
		return
	}
	proofP := proofPs[i]
	proofBetas, err := r2msg.UnmarshalProofBeta(round.Params().EC())
	if err != nil || len(proofBetas) <= i || proofBetas[i] == nil {
		errChs <- round.WrapError(fmt.Errorf("error parsing proofBetas [%d][%d]", sender, i))
		return
	}
	proofBeta := proofBetas[i]
	round.temp.cAlpha[sender][i] = r2msg.UnmarshalCAlpha()
	round.temp.cBeta[sender][i] = r2msg.UnmarshalCBeta()
	round.temp.cBetaPrm[sender][i] = r2msg.UnmarshalCBetaPrm()
	cB := round.temp.Xgamma[sender]
	alphaIj, err := accmta.AliceEndP(
		round.Params().EC(),
		round.key.PaillierSK,
		round.key.PaillierPKs[sender],
		proofP,
		proofBeta,
		round.temp.cA[i],
		round.temp.cAlpha[sender][i],
		round.temp.cBeta[sender][i],
		round.temp.cBetaPrm[sender][i],
		cB,
		round.key.GetRingPedersen(i),
	)
	if err != nil {
		errChs <- round.WrapError(fmt.Errorf("error getting alphaIJ [%d][%d] %v", sender, i, err))
		round.temp.alpha[sender] = big.NewInt(1)
		return
	}
	round.temp.alpha[sender] = alphaIj
}

func (round *round3) AliceEndDL(sender int, wg *sync.WaitGroup, errChs chan *tss.Error) {
	defer wg.Done()
	i := round.PartyID().Index
	r2msg := round.temp.signRound2Messages[sender][i].Content().(*SignRound2Message)
	proofDLs, err := r2msg.UnmarshalProofDL(round.Params().EC())
	if err != nil || len(proofDLs) <= i {
		errChs <- round.WrapError(fmt.Errorf("error getting proofDL [%d][%d]", sender, i))
		return
	}
	proofDL := proofDLs[i]
	proofNus, err := r2msg.UnmarshalProofNu(round.Params().EC())
	if err != nil || len(proofNus) <= i {
		errChs <- round.WrapError(fmt.Errorf("error getting proofDL [%d][%d]", sender, i))
		return
	}
	proofNu := proofNus[i]
	round.temp.cMu[sender][i] = r2msg.UnmarshalCMu()
	round.temp.cNu[sender][i] = r2msg.UnmarshalCNu()
	round.temp.cNuPrm[sender][i] = r2msg.UnmarshalCNuPrm()

	muIj, err := accmta.AliceEndDL(
		round.Params().EC(),
		round.key.PaillierSK,
		round.key.PaillierPKs[sender],
		proofDL,
		proofNu,
		round.temp.cA[i],
		round.temp.cMu[sender][i],
		round.temp.cNu[sender][i],
		round.temp.cNuPrm[sender][i],
		round.temp.bigWs[sender],
		round.key.GetRingPedersen(i),
	)
	if err != nil {
		errChs <- round.WrapError(fmt.Errorf("error getting proofP [%d][%d]", sender, i))
		return
	}
	round.temp.mu[sender] = muIj
}

func (round *round3) ComputeDs() {
	for i, _ := range round.Parties().IDs() {
		modN2 := common.ModInt(round.key.PaillierPKs[i].NSquare())
		Di := round.temp.Xkgamma[i]
		if Di == nil {
			return
		}
		for j := range round.Parties().IDs() {
			if i == j {
				continue
			}
			Di = modN2.Mul(Di, round.temp.cAlpha[j][i]) // encrypted under pki
			Di = modN2.Mul(Di, round.temp.cBeta[i][j])  // encrypted under pki
		}
		round.temp.D[i] = Di
	}
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

func (round *round3) ComputeProofs() (*big.Int, []*zkproofs.DecProof, *tss.Error) {
	round.ComputeDs()
	round.ComputeDelta()
	i := round.PartyID().Index
	modQ := common.ModInt(round.Params().EC().Params().N)

	if round.temp.delta[i] == nil {
		return nil, nil, round.WrapError(fmt.Errorf("%d could not compute Delta", i))
	}

	if round.temp.D[i] == nil {
		return nil, nil, round.WrapError(fmt.Errorf("%d could not compute D", i))
	}

	ski := round.key.PaillierSK
	d, rho, errd := ski.DecryptFull(round.temp.D[i])
	if errd != nil {
		return nil, nil, round.WrapError(fmt.Errorf("could not decrypt D"))
	}

	statement := &zkproofs.DecStatement{
		Q:   round.Params().EC().Params().N,
		Ell: zkproofs.GetEll(round.Params().EC()),
		N0:  ski.PublicKey.N,
		C:   round.temp.D[i],
		X:   modQ.Mod(d),
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
	return d, proofs, nil
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
