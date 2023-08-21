// Copyright 2023 Circle

package cggplus

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto/zkproofs"
	"github.com/bnb-chain/tss-lib/tss"
)

func (round *finalization) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 6
	round.started = true
	round.resetOK()

	partyCount := len(round.Parties().IDs())
	errChs := make(chan *tss.Error, partyCount*partyCount)
	wg := sync.WaitGroup{}
	go func() {
		defer wg.Done()
		round.VerifyRound5Messages(errChs)
	}()
	wg.Wait()
	close(errChs)
	err := round.WrapErrorChs(round.PartyID(), errChs, "Failed to process round 5 messages")
	if err != nil {
		return err
	}

	sumS := round.GetSumS()

	recid := 0
	// byte v = if(R.X > curve.N) then 2 else 0) | (if R.Y.IsEven then 0 else 1);
	if round.temp.rx.Cmp(round.Params().EC().Params().N) > 0 {
		recid = 2
	}
	if round.temp.ry.Bit(0) != 0 {
		recid |= 1
	}

	// This is copied from:
	// https://github.com/btcsuite/btcd/blob/c26ffa870fd817666a857af1bf6498fabba1ffe3/btcec/signature.go#L442-L444
	// This is needed because of tendermint checks here:
	// https://github.com/tendermint/tendermint/blob/d9481e3648450cb99e15c6a070c1fb69aa0c255b/crypto/secp256k1/secp256k1_nocgo.go#L43-L47
	secp256k1halfN := new(big.Int).Rsh(round.Params().EC().Params().N, 1)
	if sumS.Cmp(secp256k1halfN) > 0 {
		sumS.Sub(round.Params().EC().Params().N, sumS)
		recid ^= 1
	}

	// save the signature for final output
	bitSizeInBytes := round.Params().EC().Params().BitSize / 8
	round.data.R = padToLengthBytesInPlace(round.temp.rx.Bytes(), bitSizeInBytes)
	round.data.S = padToLengthBytesInPlace(sumS.Bytes(), bitSizeInBytes)
	round.data.Signature = append(round.data.R, round.data.S...)
	round.data.SignatureRecovery = []byte{byte(recid)}
	round.data.M = round.temp.m.Bytes()

	pk := ecdsa.PublicKey{
		Curve: round.Params().EC(),
		X:     round.key.ECDSAPub.X(),
		Y:     round.key.ECDSAPub.Y(),
	}
	ok := ecdsa.Verify(&pk, round.temp.m.Bytes(), round.temp.rx, sumS)
	if !ok {
		return round.WrapError(fmt.Errorf("signature verification failed"))
	}

	round.end <- *round.data

	return nil
}

func (round *finalization) GetSumS() *big.Int {
	sumS := round.temp.sigma
	modQ := common.ModInt(round.Params().EC().Params().N)

	for j := range round.Parties().IDs() {
		round.ok[j] = true
		if j == round.PartyID().Index {
			continue
		}
		r5msg := round.temp.signRound5Messages[j].Content().(*SignRound5Message)
		sumS = modQ.Add(sumS, r5msg.UnmarshalSigma())
	}
	return sumS
}

func (round *round5) ComputeBigSigma(i int, bigHHat *big.Int) *tss.Error {
	pki := round.key.PaillierPKs[i]
	prod := bigHHat
	var err error
	for j := range round.Parties().IDs() {
		if j == i {
			continue
		}
		temp, err := round.key.PaillierPKs[i].HomoAdd(round.temp.bigDHat[j][i], round.temp.bigFHat[i][j])
		if err != nil {
			return round.WrapError(fmt.Errorf("could not compute bigSigma a"))
		}
		prod, err = round.key.PaillierPKs[i].HomoAdd(prod, temp)
		if err != nil {
			return round.WrapError(fmt.Errorf("could not compute bigSigma b"))
		}
	}
	prod, err = pki.HomoMult(round.temp.rx, prod)
	if err != nil {
		return round.WrapError(fmt.Errorf("could not compute bigSigma c"))
	}
	if round.temp.bigK == nil {
		return round.WrapError(fmt.Errorf("something wrong with bigK[%d]", i))
	}
	prodPrime, err := pki.HomoMult(round.temp.m, round.temp.bigK[i])
	if err != nil {
		return round.WrapError(fmt.Errorf("could not compute bigSigma d"))
	}
	bigSigma, err := pki.HomoAdd(prod, prodPrime)
	if err != nil {
		return round.WrapError(fmt.Errorf("could not compute bigSigma e"))
	}
	round.temp.bigSigma[i] = bigSigma
	return nil
}

func (round *finalization) VerifyRound5Messages(errChs chan *tss.Error) {
	i := round.PartyID().Index
	rp := round.key.GetRingPedersen(i)
	wg := sync.WaitGroup{}
	for j, msg := range round.temp.signRound5Messages {
		r5msg := msg.Content().(*SignRound5Message)
		if j == i {
			continue
		}
		wg.Add(1)
		go func(j int, r5msg *SignRound5Message) {
			defer wg.Done()
			bigHHat := r5msg.UnmarshalBigHHat()
			terr := round.ComputeBigSigma(j, bigHHat)
			if terr != nil {
				errChs <- terr
				return
			}

			pkj := round.key.PaillierPKs[j]
			statementBigHHat := &zkproofs.MulStarStatement{
				Ell: zkproofs.GetEll(round.Params().EC()),
				N0:  pkj.N,
				C:   round.temp.bigK[j],
				D:   bigHHat,
				X:   round.temp.bigWs[j],
			}
			proof, err := r5msg.UnmarshalBigHHatProof(round.Params().EC())
			if err != nil || !proof[i].Verify(statementBigHHat, rp) {
				errChs <- round.WrapError(errors.New(fmt.Sprintf("bad proof from party %d.", j)))
				return
			}

			sigma := r5msg.UnmarshalSigma()
			ec := round.Params().EC()
			statement := &zkproofs.DecStatement{
				Q:   ec.Params().N,
				Ell: zkproofs.GetEll(ec),
				N0:  pkj.N,
				C:   round.temp.bigSigma[j],
				X:   sigma,
			}
			proofSigma, err := r5msg.UnmarshalSigmaProof(ec)
			if err != nil {
				errChs <- round.WrapError(errors.New(fmt.Sprintf("failed to parse proof from party %d.", j)))
				return
			}
			if !proofSigma[i].Verify(statement, rp) {
				errChs <- round.WrapError(errors.New(fmt.Sprintf("failed to verify proof from party %d.", j)))
				return
			}
		}(j, r5msg)
	}
	wg.Wait()
}

func (round *finalization) CanAccept(msg tss.ParsedMessage) bool {
	// not expecting any incoming messages in this round
	return false
}

func (round *finalization) Update() (bool, *tss.Error) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *finalization) NextRound() tss.Round {
	return nil // finished!
}

func padToLengthBytesInPlace(src []byte, length int) []byte {
	oriLen := len(src)
	if oriLen < length {
		for i := 0; i < length-oriLen; i++ {
			src = append([]byte{0}, src...)
		}
	}
	return src
}
