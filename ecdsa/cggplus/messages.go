// Copyright (c) 2023, Circle Internet Financial, LTD.
// All rights reserved
package cggplus

import (
	"crypto/elliptic"
	"math/big"
	"strconv"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/crypto/zkproofs"
	"github.com/bnb-chain/tss-lib/tss"
)

var (
	// Ensure that signing messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*SignRound1Message)(nil),
		(*SignRound2Message1)(nil),
		(*SignRound2Message2)(nil),
		(*SignRound3Message)(nil),
		(*SignRound4Message)(nil),
		(*SignRound5Message)(nil),
	}
)

func NewSignRound1Message(
	from *tss.PartyID,
	bigK, bigG *big.Int,
	psiArray []*zkproofs.EncProof,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	pPsi := zkproofs.ProofArrayToBytes(psiArray)
	content := &SignRound1Message{
		Psi:  pPsi[:],
		BigG: bigG.Bytes(),
		BigK: bigK.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound1Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.GetBigG()) &&
		common.NonEmptyBytes(m.GetBigK())
}

func (m *SignRound1Message) UnmarshalBigG() *big.Int {
	return new(big.Int).SetBytes(m.GetBigG())
}

func (m *SignRound1Message) UnmarshalBigK() *big.Int {
	return new(big.Int).SetBytes(m.GetBigK())
}

func (m *SignRound1Message) UnmarshalPsi() ([]*zkproofs.EncProof, error) {
	return zkproofs.ProofArrayFromBytes[*zkproofs.EncProof](nil, m.GetPsi())
}

func NewSignRound2Message1(
	recipient, from *tss.PartyID,
	bigD, bigDHat, bigF, bigFHat *big.Int,
	psiArray, psiHatArray []*zkproofs.AffGInvProof,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	pPsi := zkproofs.ProofArrayToBytes(psiArray)
	pPsiHat := zkproofs.ProofArrayToBytes(psiHatArray)
	content := &SignRound2Message1{
		Recipient: []byte(strconv.Itoa(recipient.Index)),
		BigD:      bigD.Bytes(),
		BigDHat:   bigDHat.Bytes(),
		BigF:      bigF.Bytes(),
		BigFHat:   bigFHat.Bytes(),
		Psi:       pPsi[:],
		PsiHat:    pPsiHat[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound2Message1) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.GetRecipient()) &&
		common.NonEmptyBytes(m.GetBigD()) &&
		common.NonEmptyBytes(m.GetBigDHat()) &&
		common.NonEmptyBytes(m.GetBigF()) &&
		common.NonEmptyBytes(m.GetBigFHat())
}

func (m *SignRound2Message1) UnmarshalRecipient() int {
	x, err := strconv.Atoi(string(m.GetRecipient()))
	if err != nil {
		return -1
	}
	return x
}

func (m *SignRound2Message1) UnmarshalBigD() *big.Int {
	return new(big.Int).SetBytes(m.GetBigD())
}

func (m *SignRound2Message1) UnmarshalBigDHat() *big.Int {
	return new(big.Int).SetBytes(m.GetBigDHat())
}

func (m *SignRound2Message1) UnmarshalBigF() *big.Int {
	return new(big.Int).SetBytes(m.GetBigF())
}

func (m *SignRound2Message1) UnmarshalBigFHat() *big.Int {
	return new(big.Int).SetBytes(m.GetBigFHat())
}

func (m *SignRound2Message1) UnmarshalPsi(ec elliptic.Curve) ([]*zkproofs.AffGInvProof, error) {
	return zkproofs.ProofArrayFromBytes[*zkproofs.AffGInvProof](ec, m.GetPsi())
}

func (m *SignRound2Message1) UnmarshalPsiHat(ec elliptic.Curve) ([]*zkproofs.AffGInvProof, error) {
	return zkproofs.ProofArrayFromBytes[*zkproofs.AffGInvProof](ec, m.GetPsiHat())
}

func NewSignRound2Message2(
	from *tss.PartyID,
	pointGamma *crypto.ECPoint,
	psiPrimeArray []*zkproofs.LogStarProof,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	pGamma := PointToBytes(pointGamma)
	pPsiPrime := zkproofs.ProofArrayToBytes(psiPrimeArray)
	content := &SignRound2Message2{
		PointGamma: pGamma[:],
		PsiPrime:   pPsiPrime[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound2Message2) ValidateBasic() bool {
	return m != nil &&
		m.GetPointGamma() != nil &&
		common.NonEmptyBytes(m.GetPointGamma()[0]) &&
		common.NonEmptyBytes(m.GetPointGamma()[1])
}

func (m *SignRound2Message2) UnmarshalGamma(ec elliptic.Curve) (*crypto.ECPoint, error) {
	bzs := m.GetPointGamma()
	point, err := BytesToPoint(ec, bzs)
	return point, err
}

func (m *SignRound2Message2) UnmarshalPsiPrime(ec elliptic.Curve) ([]*zkproofs.LogStarProof, error) {
	return zkproofs.ProofArrayFromBytes[*zkproofs.LogStarProof](ec, m.GetPsiPrime())
}

func NewSignRound3Message(
	from *tss.PartyID,
	delta *big.Int,
	bigDelta *crypto.ECPoint,
	H *big.Int,
	psiPrimePrimeArray []*zkproofs.LogStarProof,
	hProof *zkproofs.MulProof,
	deltaProofArray []*zkproofs.DecProof,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	pBigDelta := PointToBytes(bigDelta)
	pPsiPrimePrime := zkproofs.ProofArrayToBytes(psiPrimePrimeArray)
	pDeltaProof := zkproofs.ProofArrayToBytes(deltaProofArray)
	phProof := hProof.Bytes()
	content := &SignRound3Message{
		Delta:         delta.Bytes(),
		H:             H.Bytes(),
		BigDelta:      pBigDelta[:],
		PsiPrimePrime: pPsiPrimePrime[:],
		DeltaProof:    pDeltaProof[:],
		HProof:        phProof[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound3Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.GetDelta())
}

func (m *SignRound3Message) UnmarshalDelta() *big.Int {
	return new(big.Int).SetBytes(m.GetDelta())
}

func (m *SignRound3Message) UnmarshalBigH() *big.Int {
	return new(big.Int).SetBytes(m.GetH())
}

func (m *SignRound3Message) UnmarshalBigDelta(ec elliptic.Curve) (*crypto.ECPoint, error) {
	bzs := m.GetBigDelta()
	point, err := BytesToPoint(ec, bzs)
	return point, err
}

func (m *SignRound3Message) UnmarshalPsiPrimePrime(ec elliptic.Curve) ([]*zkproofs.LogStarProof, error) {
	return zkproofs.ProofArrayFromBytes[*zkproofs.LogStarProof](ec, m.GetPsiPrimePrime())
}

func (m *SignRound3Message) UnmarshalDeltaProof(ec elliptic.Curve) ([]*zkproofs.DecProof, error) {
	return zkproofs.ProofArrayFromBytes[*zkproofs.DecProof](ec, m.GetDeltaProof())
}

func (m *SignRound3Message) UnmarshalHProof() (*zkproofs.MulProof, error) {
	return zkproofs.MulProofFromBytes(m.GetHProof())
}

func NewSignRound4Message(
	from *tss.PartyID,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &SignRound4Message{}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound4Message) ValidateBasic() bool {
	return true
}

func NewSignRound5Message(
	from *tss.PartyID,
	sigma, bigHHat *big.Int,
	bigHHatProofArray []*zkproofs.MulStarProof,
	bigSigmaProofArray []*zkproofs.DecProof,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	pBigHHatProof := zkproofs.ProofArrayToBytes(bigHHatProofArray)
	pBigSigmaProof := zkproofs.ProofArrayToBytes(bigSigmaProofArray)
	content := &SignRound5Message{
		Sigma:         sigma.Bytes(),
		BigHHat:       bigHHat.Bytes(),
		BigHHatProof:  pBigHHatProof[:],
		BigSigmaProof: pBigSigmaProof[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound5Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.GetSigma()) &&
		common.NonEmptyBytes(m.GetBigHHat())
}

func (m *SignRound5Message) UnmarshalSigma() *big.Int {
	return new(big.Int).SetBytes(m.GetSigma())
}

func (m *SignRound5Message) UnmarshalBigHHat() *big.Int {
	return new(big.Int).SetBytes(m.GetBigHHat())
}

func (m *SignRound5Message) UnmarshalBigHHatProof(ec elliptic.Curve) ([]*zkproofs.MulStarProof, error) {
	return zkproofs.ProofArrayFromBytes[*zkproofs.MulStarProof](ec, m.GetBigHHatProof())
}

func (m *SignRound5Message) UnmarshalSigmaProof(ec elliptic.Curve) ([]*zkproofs.DecProof, error) {
	return zkproofs.ProofArrayFromBytes[*zkproofs.DecProof](ec, m.GetBigSigmaProof())
}

func PointToBytes(point *crypto.ECPoint) [][]byte {
	return [][]byte{point.X().Bytes(), point.Y().Bytes()}
}

func BytesToPoint(ec elliptic.Curve, bzs [][]byte) (*crypto.ECPoint, error) {
	point, err := crypto.NewECPoint(
		ec,
		new(big.Int).SetBytes(bzs[0]),
		new(big.Int).SetBytes(bzs[1]),
	)
	if err != nil {
		return point, err
	}
	return point, nil
}
