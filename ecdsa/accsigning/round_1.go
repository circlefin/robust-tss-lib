// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.
//
//  Portions Copyright (c) 2023, Circle Internet Financial, LTD.
//  All rights reserved
//

package accsigning

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/crypto/accmta"
	"github.com/bnb-chain/tss-lib/crypto/zkproofs"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/tss"
)

var (
	zero = big.NewInt(0)
)

func newRound1(params *tss.Parameters, key *keygen.LocalPartySaveData, data *common.SignatureData, temp *localTempData, out chan<- tss.Message, end chan<- common.SignatureData) tss.Round {
	return &round1{
		&base{params, key, data, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1}}
}

func (round *round1) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	round.number = 1
	round.started = true
	round.resetOK()
	i := round.PartyID().Index
	round.ok[i] = true

	paillierPK := round.key.PaillierSK.PublicKey
	q := round.Params().EC().Params().N

	k := common.GetRandomPositiveInt(q)
	cA, rA, err := paillierPK.EncryptAndReturnRandomness(k)
	if err != nil {
		return round.WrapError(fmt.Errorf("failed to init round1: %v", err))
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
	Xkw, rhokw, err := paillierPK.HomoMultAndReturnRandomness(round.temp.w, cA)
	if err != nil {
		return round.WrapError(fmt.Errorf("failed to get init round1"))
	}
	// C = Encrypt(k)
	// X = bigW = g^w
	// D = C^x rho^N0 mod N02
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

	// save data for later in round.temp
	round.temp.k = k
	round.temp.gamma = gamma
	round.temp.rhoxgamma = rhoxgamma
	round.temp.Xgamma[i] = Xgamma
	round.temp.Xkgamma[i] = Xkgamma
	round.temp.Xkw[i] = Xkw
	round.temp.cA[i] = cA
	round.temp.pointGamma[i] = crypto.ScalarBaseMult(round.Params().EC(), gamma)

	// P2P messages
	rpVs := round.key.GetAllRingPedersen()
	rpVs[i] = nil
	_, proofAlice, err := accmta.AliceInit(
		round.Params().EC(),
		round.key.PaillierPKs[i],
		k, rA,
		rpVs,
	)
	if err != nil {
		return round.WrapError(fmt.Errorf("failed to init mta: %v", err))
	}

	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		proofXgamma, err := zkproofs.NewEncProof(witnessXgamma, statementXgamma, rpVs[j])
		if err != nil {
			return round.WrapError(fmt.Errorf("failed to create proof Xgamma: %v", err))
		}
		proofXkw := zkproofs.NewMulStarProof(witnessXkw, statementXkw, rpVs[j])
		r1msg1 := NewSignRound1Message1(
			Pj, round.PartyID(),
			proofAlice[j],
			proofXgamma, proofXkw,
		)
		round.out <- r1msg1
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
