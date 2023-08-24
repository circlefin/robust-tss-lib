// Copyright 2023 Circle

package cggplus

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto/accmta"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/tss"
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

	gamma := common.GetRandomPositiveInt(q)
	bigG, err := paillierPK.Encrypt(gamma)
	if err != nil {
		return round.WrapError(errors.New("failed to init round1."))
	}

	k := common.GetRandomPositiveInt(q)
	bigK, nu, err := paillierPK.EncryptAndReturnRandomness(k)
	if err != nil {
		return round.WrapError(errors.New("failed to init round1."))
	}

	rpVs := round.key.GetAllRingPedersen()
	rpVs[i] = nil
	_, psiArray, err := accmta.AliceInit(
		round.Params().EC(),
		round.key.PaillierPKs[i],
		k, nu,
		rpVs,
	)
	if err != nil {
		return round.WrapError(errors.New("failed to init round1."))
	}

	// save data for later
	round.temp.k = k
	round.temp.gamma = gamma
	round.temp.bigG[i] = bigG
	round.temp.bigK[i] = bigK

	// broadcast
	r1msg := NewSignRound1Message(round.PartyID(), bigK, bigG, psiArray)
	round.temp.signRound1Messages[i] = r1msg
	round.out <- r1msg

	return nil
}

func (round *round1) Update() (bool, *tss.Error) {
	for j, msg1 := range round.temp.signRound1Messages {
		if round.ok[j] {
			continue
		}
		if msg1 == nil || !round.CanAccept(msg1) {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound1Message); ok {
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
