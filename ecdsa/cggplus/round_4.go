// Copyright 2023 Circle

package cggplus

import (
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto/zkproofs"
	"github.com/bnb-chain/tss-lib/tss"
)

func (round *round4) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 4
	round.started = true
	round.resetOK()

	partyCount := len(round.Parties().IDs())
	errChs := make(chan *tss.Error, partyCount*partyCount*3)
	round.VerifyRound3Messages(errChs)
	close(errChs)
	err := round.WrapErrorChs(round.PartyID(), errChs, "Failed to process round 3 messages")
	if err != nil {
		return err
	}
	/*
		err = round.ComputeFinalDelta()
		if err != nil {
			return err
		}

		proofs, err := round.ComputeProofs()
		if err != nil {
			return err
		}

		i := round.PartyID().Index
		r4msg := NewSignRound4Message(round.PartyID(), round.temp.pointGamma[i], proofs)
		round.temp.signRound4Messages[i] = r4msg
		round.out <- r4msg
	*/
	return nil
}

func (round *round4) ComputeXDelta(i int, H *big.Int) (*big.Int, error) {
    XDelta := H
	for j := range round.Parties().IDs() {
		if j == i {
			continue
		}
		temp, err := round.key.PaillierPKs[i].HomoAdd(round.temp.bigD[j][i], round.temp.bigF[i][j])
		if err != nil {
		    return nil, err
		}
		XDelta, err = round.key.PaillierPKs[i].HomoAdd(XDelta, temp)
		if err != nil {
		    return nil, err
		}
	}
    return XDelta, nil
}

func (round *round4) VerifyRound3Messages(errChs chan *tss.Error) {
	wg := sync.WaitGroup{}
	i := round.PartyID().Index
	rp := round.key.GetRingPedersen(i)
	for j, _ := range round.Parties().IDs() {
		if i == j {
			continue
		}
		wg.Add(1)
		go func(sender int) {
			defer wg.Done()
			r3msg := round.temp.signRound3Messages[sender].Content().(*SignRound3Message)
			psiPrimePrime, err := r3msg.UnmarshalPsiPrimePrime(tss.EC())
			if err != nil {
				errChs <- round.WrapError(errors.New(fmt.Sprintf("failed to parse psiPrimePrime from party %d.", sender)))
				return
			}
			round.temp.delta[sender] = r3msg.UnmarshalDelta()
			if round.temp.delta[sender] == nil {
				errChs <- round.WrapError(errors.New(fmt.Sprintf("sender %d sent nil delta.", sender)))
				return
			}
			bigDelta, err := r3msg.UnmarshalBigDelta(round.Params().EC())
			if err != nil {
				errChs <- round.WrapError(errors.New(fmt.Sprintf("sender %d sent bad bigDelta.", sender)))
				return
			}
			round.temp.bigDelta[sender] = bigDelta

			statement := &zkproofs.LogStarStatement{
				Ell: zkproofs.GetEll(round.Params().EC()),
				N0:  round.key.PaillierPKs[sender].N,
				C:   round.temp.bigK[sender],
				X:   round.temp.bigDelta[sender],
				G:   round.temp.Gamma,
			}
			if !psiPrimePrime[i].Verify(statement, rp) {
				errChs <- round.WrapError(errors.New(fmt.Sprintf("failed to verify proof from party %d.", sender)))
				return
			}

			bigH := r3msg.UnmarshalBigH()
			if bigH == nil {
				errChs <- round.WrapError(errors.New(fmt.Sprintf("sender %d sent nil bigH.", sender)))
				return
			}
			HProof, err := r3msg.UnmarshalHProof()
			if err != nil {
				errChs <- round.WrapError(errors.New(fmt.Sprintf("sender %d sent bad HProof.", sender)))
				return
			}
        	statementH := &zkproofs.MulStatement{
        		N: round.key.PaillierPKs[sender].N,
        		X: round.temp.bigG[sender],
        		Y: round.temp.bigK[sender],
        		C: bigH,
        	}
			if !HProof.Verify(statementH) {
				errChs <- round.WrapError(errors.New(fmt.Sprintf("failed to verify HProof from party %d.", sender)))
				return
			}

            XDelta, err := round.ComputeXDelta(sender, bigH)
            if err != nil {
				errChs <- round.WrapError(errors.New(fmt.Sprintf("failed to compute XDelta for party %d.", sender)))
				return
            }
			deltaProof, err := r3msg.UnmarshalDeltaProof(round.Params().EC())
			if err != nil {
				errChs <- round.WrapError(errors.New(fmt.Sprintf("sender %d sent bad deltaProof.", sender)))
				return
			}
        	statementDelta := &zkproofs.DecStatement{
        		Q:   round.Params().EC().Params().N,
        		Ell: zkproofs.GetEll(round.Params().EC()),
        		N0:  round.key.PaillierPKs[sender].N,
        		C:   XDelta,
        		X:   round.temp.delta[sender],
        	}
			if !deltaProof[i].Verify(statementDelta, rp) {
				errChs <- round.WrapError(errors.New(fmt.Sprintf("failed to verify XDeltaProof from party %d.", sender)))
				return
			}

		}(j)
	}
	wg.Wait()

}

func (round *round4) ComputeDelta() {
	modQ := common.ModInt(round.Params().EC().Params().N)
	delta := big.NewInt(0)
	for _, deltaJ := range round.temp.delta {
		delta = modQ.Add(delta, deltaJ)
	}
	round.temp.finalDelta = delta
}

/*
	func (round *round4) ComputeFinalDelta() *tss.Error {
		delta := big.NewInt(0)
		modN := common.ModInt(round.Params().EC().Params().N)
		for j, deltaJ := range round.temp.delta {
			if deltaJ == nil {
				return round.WrapError(errors.New(fmt.Sprintf("%d: nil delta[%d].", round.PartyID().Index, j)))
			}
			delta = modN.Add(delta, deltaJ)
		}
		round.temp.finalDeltaInv = modN.ModInverse(delta)
		return nil
	}

	func (round *round4) ComputeProofs() (proofs []*zkproofs.LogStarProof, err *tss.Error) {
		wg := sync.WaitGroup{}
		i := round.PartyID().Index
		err = nil
		statement := &zkproofs.LogStarStatement{
			Ell: zkproofs.GetEll(round.Params().EC()),
			N0:  round.key.PaillierSK.N,
			C:   round.temp.Xgamma[i],
			X:   round.temp.pointGamma[i],
		}
		witness := &zkproofs.LogStarWitness{
			X:   round.temp.gamma,
			Rho: round.temp.rhoxgamma,
		}

		proofs = make([]*zkproofs.LogStarProof, len(round.Parties().IDs()))
		rpVs := round.key.GetAllRingPedersen()
		for j, rp := range rpVs {
			if i == j {
				continue
			}
			wg.Add(1)
			go func(j int, rp *zkproofs.RingPedersenParams) {
				defer wg.Done()
				proofs[j] = zkproofs.NewLogStarProof(witness, statement, rp)
			}(j, rp)
		}
		wg.Wait()

		for j, pf := range proofs {
			if j != i && pf.IsNil() {
				return proofs, round.WrapError(fmt.Errorf("Failed to create proof [%d]->[%d].", i, j))
			}
		}
		return proofs, nil
	}
*/
func (round *round4) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.signRound4Messages {
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

func (round *round4) CanAccept(msg tss.ParsedMessage) bool {
	//	if _, ok := msg.Content().(*SignRound4Message); ok {
	return msg.IsBroadcast()
	//	}
	return false
}

func (round *round4) NextRound() tss.Round {
	round.started = false
	return &round5{round}
}
