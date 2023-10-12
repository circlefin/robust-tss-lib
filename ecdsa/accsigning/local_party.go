// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package accsigning

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/crypto/zkproofs"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/tss"
)

// Implements Party
// Implements Stringer
var _ tss.Party = (*LocalParty)(nil)
var _ fmt.Stringer = (*LocalParty)(nil)

type (
	LocalParty struct {
		*tss.BaseParty
		params *tss.Parameters

		keys keygen.LocalPartySaveData
		temp localTempData
		data common.SignatureData

		// outbound messaging
		out chan<- tss.Message
		end chan<- common.SignatureData
	}

	localMessageStore struct {
		signRound1Message1s,
		signRound1Message2s,
		signRound3Messages,
		signRound4Messages,
		signRound5Messages,
		signRound6Messages []tss.ParsedMessage
		signRound2Messages [][]tss.ParsedMessage
	}

	localTempData struct {
		localMessageStore

		// round 1 - all data except bigWs removed in round 5
		keyDerivationDelta,
		w,
		k,
		gamma,
		rhoxgamma *big.Int
		Xgamma,
		Xkgamma,
		Xkw,
		cA []*big.Int // [sender] -> self
		bigWs,
		pointGamma []*crypto.ECPoint // [sender] -> self

		// round 2
		beta,
		nu []*big.Int // self -> [receiver]
		cAlpha,
		cBeta,
		cBetaPrm,
		cMu,
		cNu,
		cNuPrm [][]*big.Int // [sender][receiver]

		// round 3
		delta,
		D,
		alpha,
		mu []*big.Int // [sender] -> self

		// round 4
		finalDeltaInv *big.Int

		// round 5
		bigS []*big.Int
		m,
		sigma,
		si,
		rx,
		ry *big.Int
		bigR *crypto.ECPoint
	}
)

func (temp *localTempData) CleanUpPreSigningData() {
	// round 1
	temp.w = nil
	temp.k = nil
	temp.gamma = nil
	temp.rhoxgamma = nil
	temp.Xgamma = nil
	temp.Xkgamma = nil
	temp.Xkw = nil
	temp.cA = nil
	//		leave bigWs
	temp.pointGamma = nil

	// round 2
	temp.beta = nil
	temp.nu = nil
	temp.cAlpha = nil
	temp.cBeta = nil
	temp.cBetaPrm = nil
	temp.cMu = nil
	temp.cNu = nil
	temp.cNuPrm = nil

	// round 3
	temp.delta = nil
	temp.D = nil
	temp.alpha = nil
	temp.mu = nil

	// round 4
	temp.finalDeltaInv = nil
}

func NewLocalParty(
	msg *big.Int,
	params *tss.Parameters,
	key keygen.LocalPartySaveData,
	out chan<- tss.Message,
	end chan<- common.SignatureData) tss.Party {
	return NewLocalPartyWithKDD(msg, params, key, nil, out, end)
}

// NewLocalPartyWithKDD returns a party with key derivation delta for HD support
func NewLocalPartyWithKDD(
	msg *big.Int,
	params *tss.Parameters,
	key keygen.LocalPartySaveData,
	keyDerivationDelta *big.Int,
	out chan<- tss.Message,
	end chan<- common.SignatureData,
) tss.Party {
	partyCount := len(params.Parties().IDs())
	p := &LocalParty{
		BaseParty: new(tss.BaseParty),
		params:    params,
		keys:      keygen.BuildLocalSaveDataSubset(key, params.Parties().IDs()),
		temp:      localTempData{},
		data:      common.SignatureData{},
		out:       out,
		end:       end,
	}
	// msgs init
	p.temp.signRound1Message1s = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound1Message2s = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound2Messages = Make2DParsedMessage(partyCount)
	p.temp.signRound3Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound4Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound5Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound6Messages = make([]tss.ParsedMessage, partyCount)

	// temp data init
	p.temp.keyDerivationDelta = keyDerivationDelta
	p.temp.m = msg

	// round 1
	p.temp.Xkw = make([]*big.Int, partyCount)
	p.temp.Xgamma = make([]*big.Int, partyCount)
	p.temp.Xkgamma = make([]*big.Int, partyCount)
	p.temp.cA = make([]*big.Int, partyCount)
	p.temp.bigWs = make([]*crypto.ECPoint, partyCount)
	p.temp.pointGamma = make([]*crypto.ECPoint, partyCount)

	// round 2
	p.temp.cAlpha = Make2DSlice[*big.Int](partyCount)
	p.temp.cBeta = Make2DSlice[*big.Int](partyCount)
	p.temp.cBetaPrm = Make2DSlice[*big.Int](partyCount)
	p.temp.cMu = Make2DSlice[*big.Int](partyCount)
	p.temp.cNu = Make2DSlice[*big.Int](partyCount)
	p.temp.cNuPrm = Make2DSlice[*big.Int](partyCount)
	p.temp.beta = make([]*big.Int, partyCount)
	p.temp.nu = make([]*big.Int, partyCount)

	// round 3
	p.temp.alpha = make([]*big.Int, partyCount)
	p.temp.mu = make([]*big.Int, partyCount)
	p.temp.D = make([]*big.Int, partyCount)
	p.temp.delta = make([]*big.Int, partyCount)

	p.temp.bigS = make([]*big.Int, partyCount)

	return p
}

func Make2DParsedMessage(dim int) [][]tss.ParsedMessage {
	out := make([][]tss.ParsedMessage, dim)
	for i, _ := range out {
		out[i] = make([]tss.ParsedMessage, dim)
	}
	return out
}

func Make2DSlice[K *big.Int | *zkproofs.AffPProof | *zkproofs.AffGProof | *zkproofs.DecProof](dim int) [][]K {
	out := make([][]K, dim)
	for i, _ := range out {
		out[i] = make([]K, dim)
	}
	return out
}

func (p *LocalParty) FirstRound() tss.Round {
	return newRound1(p.params, &p.keys, &p.data, &p.temp, p.out, p.end)
}

func (p *LocalParty) Start() *tss.Error {
	return tss.BaseStart(p, TaskName, func(round tss.Round) *tss.Error {
		round1, ok := round.(*round1)
		if !ok {
			return round.WrapError(errors.New("unable to Start(). party is in an unexpected round"))
		}
		if err := round1.prepare(); err != nil {
			return round.WrapError(err)
		}
		return nil
	})
}

func (p *LocalParty) Update(msg tss.ParsedMessage) (ok bool, err *tss.Error) {
	return tss.BaseUpdate(p, msg, TaskName)
}

func (p *LocalParty) UpdateFromBytes(wireBytes []byte, from *tss.PartyID, isBroadcast bool) (bool, *tss.Error) {
	msg, err := tss.ParseWireMessage(wireBytes, from, isBroadcast)
	if err != nil {
		return false, p.WrapError(err)
	}
	return p.Update(msg)
}

func (p *LocalParty) ValidateMessage(msg tss.ParsedMessage) (bool, *tss.Error) {
	if ok, err := p.BaseParty.ValidateMessage(msg); !ok || err != nil {
		return ok, err
	}
	// check that the message's "from index" will fit into the array
	if maxFromIdx := len(p.params.Parties().IDs()) - 1; maxFromIdx < msg.GetFrom().Index {
		return false, p.WrapError(fmt.Errorf("received msg with a sender index too great (%d <= %d)",
			maxFromIdx, msg.GetFrom().Index), msg.GetFrom())
	}
	return true, nil
}

func (p *LocalParty) StoreMessage(msg tss.ParsedMessage) (bool, *tss.Error) {
	// ValidateBasic is cheap; double-check the message here in case the public StoreMessage was called externally
	if ok, err := p.ValidateMessage(msg); !ok || err != nil {
		return ok, err
	}
	fromPIdx := msg.GetFrom().Index

	// switch/case is necessary to store any messages beyond current round
	// this does not handle message replays. we expect the caller to apply replay and spoofing protection.
	switch msg.Content().(type) {
	case *SignRound1Message1:
		p.temp.signRound1Message1s[fromPIdx] = msg
	case *SignRound1Message2:
		p.temp.signRound1Message2s[fromPIdx] = msg
	case *SignRound2Message:
		r2msg := msg.Content().(*SignRound2Message)
		toPIdx := r2msg.UnmarshalRecipient()
		p.temp.signRound2Messages[fromPIdx][toPIdx] = msg
	case *SignRound3Message:
		p.temp.signRound3Messages[fromPIdx] = msg
	case *SignRound4Message:
		p.temp.signRound4Messages[fromPIdx] = msg
	case *SignRound5Message:
		p.temp.signRound5Messages[fromPIdx] = msg
	default: // unrecognised message, just ignore!
		common.Logger.Warningf("unrecognised message ignored: %v", msg)
		return false, nil
	}
	return true, nil
}

func (p *LocalParty) PartyID() *tss.PartyID {
	return p.params.PartyID()
}

func (p *LocalParty) String() string {
	return fmt.Sprintf("id: %s, %s", p.PartyID(), p.BaseParty.String())
}
