// Copyright 2023 Circle
//
// This file implements round 1 of the accountable GG18 protocol.
package accsigning

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/crypto/accmta"
	"github.com/bnb-chain/tss-lib/crypto/paillier"
	"github.com/bnb-chain/tss-lib/crypto/zkproofs"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/tss"
)

var (
	zero = big.NewInt(0)
)

// round 1 represents round 1 of the signing part of the GG18 ECDSA TSS spec (Gennaro, Goldfeder; 2018)
func newRound1(params *tss.Parameters, key *keygen.LocalPartySaveData, data *common.SignatureData, temp *localTempData, out chan<- tss.Message, end chan<- common.SignatureData) tss.Round {
	return &round1{
		&base{params, key, data, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1}}
}

func (round *round1) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	// Spec requires calculate H(M) here,
	// but considered different blockchain use different hash function we accept the converted big.Int
	// if this big.Int is not belongs to Zq, the client might not comply with common rule (for ECDSA):
	// https://github.com/btcsuite/btcd/blob/c26ffa870fd817666a857af1bf6498fabba1ffe3/btcec/signature.go#L263
	if round.temp.m.Cmp(round.Params().EC().Params().N) >= 0 {
		return round.WrapError(errors.New("hashed message is not valid"))
	}

	round.number = 1
	round.started = true
	round.resetOK()
	i := round.PartyID().Index
	round.ok[i] = true

	paillierSK := round.key.PaillierSK
	paillierPK := &paillier.PublicKey{N: paillierSK.N}
	q := round.Params().EC().Params().N

	k := common.GetRandomPositiveInt(q)
	cA, rA, err := paillierPK.EncryptAndReturnRandomness(k)
	if err != nil {
		return round.WrapError(fmt.Errorf("failed to init round1: %v", err))
	}
	witnessXk := &zkproofs.EncWitness{
		K:   k,
		Rho: rA,
	}
	statementXk := &zkproofs.EncStatement{
		EC: round.Params().EC(),
		N0: paillierPK.N,
		K:  cA,
	}

	gamma := common.GetRandomPositiveInt(q)
	Xgamma, rhoxgamma, err := paillierPK.EncryptAndReturnRandomness(gamma)
	if err != nil {
		return round.WrapError(fmt.Errorf("failed to init round1: %v", err))
	}
	witnessXgamma := &zkproofs.EncWitness{
		K:   gamma,
		Rho: rhoxgamma,
	}
	statementXgamma := &zkproofs.EncStatement{
		EC: round.Params().EC(),
		N0: paillierPK.N,
		K:  Xgamma,
	}

	// Xkgamma = Xk^gamma rhoxkgamma^N  mod N2
	// C = Y^gamma * rhoxkgamma^N mod N2
	Xkgamma, rhoxkgamma, err := paillierPK.HomoMultAndReturnRandomness(gamma, cA)
	if err != nil {
		return round.WrapError(fmt.Errorf("failed to init round1: %v", err))
	}
	witnessXkgamma := &zkproofs.MulWitness{
		X:    gamma,
		Rho:  rhoxkgamma,
		Rhox: rhoxgamma,
	}
	statementXkgamma := &zkproofs.MulStatement{
		N: paillierPK.N,
		X: Xgamma,
		Y: cA,
		C: Xkgamma,
	}

	bigW := round.temp.bigWs[round.PartyID().Index]
	//	kw := common.ModInt(q).Mul(k, round.temp.w)
	Xkw, rhokw, err := paillierPK.HomoMultAndReturnRandomness(round.temp.w, cA)
	if err != nil {
		return round.WrapError(fmt.Errorf("failed to get init round1"))
	}
	// C = Encrypt(k)
	// X = bigW = g^w
	// D = C^x rho^N0 mod N02
	// Xkw = Xk^w rho^N mod N2
	witnessXkw := &zkproofs.MulStarWitness{
		X:   round.temp.w,
		Rho: rhokw,
	}
	statementXkw := &zkproofs.MulStarStatement{
		Ell: zkproofs.GetEll(round.Params().EC()),
		N0:  paillierPK.N,
		C:   cA,
		D:   Xkw,
		X:   bigW,
	}

	// save data for later in round.temp (todo)

	pointGamma := crypto.ScalarBaseMult(round.Params().EC(), gamma)
	//	cmt := commitments.NewHashCommitment(pointGamma.X(), pointGamma.Y())
	round.temp.k = k
	round.temp.gamma = gamma
	round.temp.pointGamma = pointGamma
	round.temp.Xgamma[i] = Xgamma
	round.temp.Xkgamma[i] = Xkgamma
	round.temp.cA[i] = cA
	//	round.temp.deCommit = cmt.D

	// messages for individual participants
	// share conversion and zkproofs using verifier Ring Pedersen parameters
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		ringPedersenJ := round.key.GetRingPedersen(j)
		_, proofAlice, err := accmta.AliceInit(
			round.Params().EC(),
			round.key.PaillierPKs[i],
			k, rA,
			ringPedersenJ,
		)
		if err != nil {
			return round.WrapError(fmt.Errorf("failed to init mta: %v", err))
		}

		proofXk, err := zkproofs.NewEncProof(witnessXk, statementXk, ringPedersenJ)
		if err != nil {
			return round.WrapError(fmt.Errorf("failed to create proof Xk: %v", err))
		}
		proofXgamma, err := zkproofs.NewEncProof(witnessXgamma, statementXgamma, ringPedersenJ)
		if err != nil {
			return round.WrapError(fmt.Errorf("failed to create proof Xgamma: %v", err))
		}
		proofXkw := zkproofs.NewMulStarProof(witnessXkw, statementXkw, ringPedersenJ)
		r1msg1 := NewSignRound1Message1(
			Pj, round.PartyID(),
			proofAlice,
			proofXk, proofXgamma, proofXkw,
		)
		round.out <- r1msg1
		if r1msg1.GetTo() == nil || len(r1msg1.GetTo()) == 0 {
			return round.WrapError(fmt.Errorf("failed to set r1msg1.To"))
		}
	}

	// broadcast
	proofXkgamma := zkproofs.NewMulProof(witnessXkgamma, statementXkgamma)
	r1msg2 := NewSignRound1Message2(round.PartyID(), cA, Xgamma, Xkgamma, Xkw, proofXkgamma)
	round.temp.signRound1Message2s[i] = r1msg2
	round.out <- r1msg2

	return nil
}

func (round *round1) Update() (bool, *tss.Error) {
	for j, msg1 := range round.temp.signRound1Message1s {
		if round.ok[j] {
			continue
		}
		if msg1 == nil || !round.CanAccept(msg1) {
			return false, nil
		}
		msg2 := round.temp.signRound1Message2s[j]
		if msg2 == nil || !round.CanAccept(msg2) {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound1Message1); ok {
		return !msg.IsBroadcast()
	}
	if _, ok := msg.Content().(*SignRound1Message2); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}

// ----- //

// helper to call into PrepareForSigning()
func (round *round1) prepare() error {
	i := round.PartyID().Index

	xi := round.key.Xi
	ks := round.key.Ks
	bigXs := round.key.BigXj

	if round.temp.keyDerivationDelta != nil {
		// adding the key derivation delta to the xi's
		// Suppose x has shamir shares x_0,     x_1,     ..., x_n
		// So x + D has shamir shares  x_0 + D, x_1 + D, ..., x_n + D
		mod := common.ModInt(round.Params().EC().Params().N)
		xi = mod.Add(round.temp.keyDerivationDelta, xi)
		round.key.Xi = xi
	}

	if round.Threshold()+1 > len(ks) {
		return fmt.Errorf("t+1=%d is not satisfied by the key count of %d", round.Threshold()+1, len(ks))
	}
	wi, bigWs := signing.PrepareForSigning(round.Params().EC(), i, len(ks), xi, ks, bigXs)

	round.temp.w = wi
	round.temp.bigWs = bigWs
	return nil
}
