// Copyright 2023 Circle
//

package accsigning

import (
	"errors"
	"fmt"
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
		for recipient, _ := range round.Parties().IDs() {
			if sender == i || sender == recipient {
				continue
			}

			if i == recipient {
				wg.Add(2)
				go round.AliceEndP(sender, &wg, errChs)
				go round.AliceEndDL(sender, &wg, errChs)
			} else {
				wg.Add(1)
				go round.Round3Verify(sender, recipient, &wg, errChs)
			}
		}
	}
	wg.Wait()
	close(errChs)

	// consume error channels; wait for goroutines
	culprits := make([]*tss.PartyID, 0, len(round.Parties().IDs()))
	for err := range errChs {
		culprits = append(culprits, err.Culprits()...)
	}
	if len(culprits) > 0 {
		return round.WrapError(errors.New("failed to calculate AliceEndP or AliceEndDL"), culprits...)
	}

	proofs, err := round.ComputeProofs()
	if err != nil {
		return err
	}

	r3msg := NewSignRound3Message(
		round.PartyID(),
		round.temp.delta[i],
		proofs,
	)
	round.temp.signRound3Messages[round.PartyID().Index] = r3msg
	round.out <- r3msg

	return nil
}

func (round *round3) Round3Verify(sender, recipient int, wg *sync.WaitGroup, errChs chan *tss.Error) {
	defer wg.Done()
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
		errChs <- round.WrapError(fmt.Errorf("failed to verify proof [%d][%d][%d]", sender, recipient, verifier))
		return
	}

	proofDLs, err := r2msg.UnmarshalProofDL(round.Params().EC())
	if err != nil || len(proofDLs) <= verifier {
		errChs <- round.WrapError(fmt.Errorf("error getting proofP [%d][%d]", sender, recipient))
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
		round.temp.bigWs[recipient],
		round.key.GetRingPedersen(verifier),
	)
	if !ok {
		errChs <- round.WrapError(fmt.Errorf("failed to verify proof [%d][%d][%d]", sender, recipient, verifier))
		return
	}
}

func (round *round3) AliceEndP(sender int, wg *sync.WaitGroup, errChs chan *tss.Error) {
	defer wg.Done()
	i := round.PartyID().Index
	r2msg := round.temp.signRound2Messages[sender][i].Content().(*SignRound2Message)
	proofPs, err := r2msg.UnmarshalProofP()
	if err != nil || len(proofPs) <= i {
		errChs <- round.WrapError(fmt.Errorf("error getting proofP [%d][%d]", sender, i))
		return
	}
	proofP := proofPs[i]
	round.temp.cAlpha[sender][i] = r2msg.UnmarshalCAlpha()
	round.temp.cBetaPrm[sender][i] = r2msg.UnmarshalCBetaPrm()
	cB := round.temp.Xgamma[sender]
	alphaIj, err := accmta.AliceEndP(
		round.Params().EC(),
		round.key.PaillierSK,
		round.key.PaillierPKs[sender],
		proofP,
		round.temp.cA[i],
		round.temp.cAlpha[sender][i],
		round.temp.cBetaPrm[sender][i],
		cB,
		round.key.GetRingPedersen(i),
	)
	if err != nil {
		errChs <- round.WrapError(fmt.Errorf("error getting proofP [%d][%d]", sender, i))
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
	round.temp.cMu[sender][i] = r2msg.UnmarshalCMu()
	round.temp.cNuPrm[sender][i] = r2msg.UnmarshalCNuPrm()

	muIj, err := accmta.AliceEndDL(
		round.Params().EC(),
		round.key.PaillierSK,
		round.key.PaillierPKs[sender],
		proofDL,
		round.temp.cA[i],
		round.temp.cMu[sender][i],
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

func (round *round3) ComputeProofs() (proofs []*zkproofs.DecProof, err *tss.Error) {
	wg := sync.WaitGroup{}
	err = nil
	for i := range round.Parties().IDs() {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			Di := round.temp.Xkgamma[i]
			pki := round.key.PaillierPKs[i]
			modN2 := common.ModInt(pki.NSquare())
			for j := range round.Parties().IDs() {
				if j == i {
					continue
				}
				cBeta, erri := pki.HomoMultInv(round.temp.cBetaPrm[i][j]) // encrypted under pki
				if erri != nil {
					err = round.WrapError(erri)
					return
				}
				Di = modN2.Mul(Di, round.temp.cAlpha[j][i]) // encrypted under pki
				Di = modN2.Mul(Di, cBeta)                   // encrypted under pki
			}
			round.temp.D[i] = Di
		}(i)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		i := round.PartyID().Index
		modN := common.ModInt(round.Params().EC().Params().N)
		delta := modN.Mul(round.temp.k, round.temp.gamma)
		sigma := modN.Mul(round.temp.k, round.temp.w)
		for j := range round.Parties().IDs() {
			if j == round.PartyID().Index {
				continue
			}
			delta = modN.Add(delta, round.temp.alpha[j].Add(round.temp.alpha[j], round.temp.beta[j]))
			sigma = modN.Add(sigma, round.temp.mu[j].Add(round.temp.mu[j], round.temp.nu[j]))
		}
		round.temp.delta[i] = delta
		round.temp.sigma[i] = sigma
	}()
	wg.Wait()
	if err != nil {
		return nil, err
	}

	i := round.PartyID().Index
	ski := round.key.PaillierSK
	statement := &zkproofs.DecStatement{
		Q:   round.Params().EC().Params().N,
		Ell: zkproofs.GetEll(round.Params().EC()),
		N0:  ski.PublicKey.N,
		C:   round.temp.D[i],
		X:   round.temp.delta[i],
	}
	y, rho, errd := ski.DecryptFull(round.temp.D[i])
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
