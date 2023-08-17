package accsigning

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
		(*SignRound1Message1)(nil),
		(*SignRound1Message2)(nil),
		(*SignRound2Message)(nil),
		(*SignRound3Message)(nil),
		(*SignRound4Message)(nil),
	}
)

func NewSignRound1Message1(
	to, from *tss.PartyID,
	proofAlice *zkproofs.EncProof,
	proofXgamma *zkproofs.EncProof,
	proofXkw *zkproofs.MulStarProof,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}
	pa := proofAlice.Bytes()
	pXg := proofXgamma.Bytes()
	pXkw := proofXkw.Bytes()
	content := &SignRound1Message1{
		RangeProofAlice: pa[:],
		ProofXGamma:     pXg[:],
		ProofXKw:        pXkw[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound1Message1) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.GetRangeProofAlice(), zkproofs.EncProofParts) &&
		common.NonEmptyMultiBytes(m.GetProofXGamma(), zkproofs.EncProofParts) &&
		common.NonEmptyMultiBytes(m.GetProofXKw(), zkproofs.MulStarProofParts)
}

func (m *SignRound1Message1) UnmarshalRangeProofAlice() (*zkproofs.EncProof, error) {
	proof, err := new(zkproofs.EncProof).ProofFromBytes(nil, m.GetRangeProofAlice())
	if err != nil {
	    return nil, err
	}
	return proof.(*zkproofs.EncProof), nil
}

func (m *SignRound1Message1) UnmarshalProofXGamma() (*zkproofs.EncProof, error) {
	proof, err := new(zkproofs.EncProof).ProofFromBytes(nil, m.GetProofXGamma())
	if err != nil {
	    return nil, err
	}
	return proof.(*zkproofs.EncProof), nil
}

func (m *SignRound1Message1) UnmarshalProofXKw(ec elliptic.Curve) (*zkproofs.MulStarProof, error) {
	return zkproofs.MulStarProofFromBytes(ec, m.GetProofXKw())
}

func NewSignRound1Message2(
	from *tss.PartyID,
	cA, xgamma, xkgamma, xkw *big.Int,
	proofXkgamma *zkproofs.MulProof,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	pXkg := proofXkgamma.Bytes()
	content := &SignRound1Message2{
		CA:           cA.Bytes(),
		XGamma:       xgamma.Bytes(),
		XKgamma:      xkgamma.Bytes(),
		XKw:          xkw.Bytes(),
		ProofXKgamma: pXkg[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound1Message2) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.GetCA()) &&
		common.NonEmptyBytes(m.GetXGamma()) &&
		common.NonEmptyBytes(m.GetXKgamma()) &&
		common.NonEmptyBytes(m.GetXKw()) &&
		common.NonEmptyMultiBytes(m.GetProofXKgamma(), zkproofs.MulProofParts)
}

func (m *SignRound1Message2) UnmarshalCA() *big.Int {
	return new(big.Int).SetBytes(m.GetCA())
}

func (m *SignRound1Message2) UnmarshalXGamma() *big.Int {
	return new(big.Int).SetBytes(m.GetXGamma())
}

func (m *SignRound1Message2) UnmarshalXKGamma() *big.Int {
	return new(big.Int).SetBytes(m.GetXKgamma())
}

func (m *SignRound1Message2) UnmarshalXKw() *big.Int {
	return new(big.Int).SetBytes(m.GetXKw())
}

func (m *SignRound1Message2) UnmarshalProofXKgamma() (*zkproofs.MulProof, error) {
	return zkproofs.MulProofFromBytes(m.GetProofXKgamma())
}

func NewSignRound2Message(
	recipient, from *tss.PartyID,
	cAlpha, cBeta, cBetaPrm, cMu, cNu, cNuPrm *big.Int,
	proofP []*zkproofs.AffPProof,
	proofDL []*zkproofs.AffGProof,
	proofDecBeta []*zkproofs.DecProof,
	proofDecNu []*zkproofs.DecProof,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	pP := zkproofs.ProofArrayToBytes(proofP)
	pDL := zkproofs.ProofArrayToBytes(proofDL)
	dBeta := zkproofs.ProofArrayToBytes(proofDecBeta)
	dNu := zkproofs.ProofArrayToBytes(proofDecNu)
	content := &SignRound2Message{
		Recipient: []byte(strconv.Itoa(recipient.Index)),
		CAlpha:    cAlpha.Bytes(),
		CBeta:     cBeta.Bytes(),
		CBetaPrm:  cBetaPrm.Bytes(),
		CMu:       cMu.Bytes(),
		CNu:       cNu.Bytes(),
		CNuPrm:    cNuPrm.Bytes(),
		ProofP:    pP[:],
		ProofDl:   pDL[:],
		ProofBeta: dBeta[:],
		ProofNu:   dNu[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound2Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.GetRecipient()) &&
		common.NonEmptyBytes(m.GetCAlpha()) &&
		common.NonEmptyBytes(m.GetCBetaPrm()) &&
		common.NonEmptyBytes(m.GetCBeta()) &&
		common.NonEmptyBytes(m.GetCMu()) &&
		common.NonEmptyBytes(m.GetCNu()) &&
		common.NonEmptyBytes(m.GetCNuPrm())
}

func (m *SignRound2Message) UnmarshalRecipient() int {
	x, err := strconv.Atoi(string(m.GetRecipient()))
	if err != nil {
		return -1
	}
	return x
}

func (m *SignRound2Message) UnmarshalCAlpha() *big.Int {
	return new(big.Int).SetBytes(m.GetCAlpha())
}

func (m *SignRound2Message) UnmarshalCBeta() *big.Int {
	return new(big.Int).SetBytes(m.GetCBeta())
}

func (m *SignRound2Message) UnmarshalCBetaPrm() *big.Int {
	return new(big.Int).SetBytes(m.GetCBetaPrm())
}

func (m *SignRound2Message) UnmarshalCMu() *big.Int {
	return new(big.Int).SetBytes(m.GetCMu())
}

func (m *SignRound2Message) UnmarshalCNu() *big.Int {
	return new(big.Int).SetBytes(m.GetCNu())
}

func (m *SignRound2Message) UnmarshalCNuPrm() *big.Int {
	return new(big.Int).SetBytes(m.GetCNuPrm())
}

func (m *SignRound2Message) UnmarshalProofP() ([]*zkproofs.AffPProof, error) {
	return zkproofs.ProofArrayFromBytes[*zkproofs.AffPProof](nil, m.GetProofP())
}

func (m *SignRound2Message) UnmarshalProofDL(ec elliptic.Curve) ([]*zkproofs.AffGProof, error) {
	return zkproofs.ProofArrayFromBytes[*zkproofs.AffGProof](ec, m.GetProofDl())
}

func (m *SignRound2Message) UnmarshalProofBeta(ec elliptic.Curve) ([]*zkproofs.DecProof, error) {
	return zkproofs.ProofArrayFromBytes[*zkproofs.DecProof](ec, m.GetProofBeta())
}

func (m *SignRound2Message) UnmarshalProofNu(ec elliptic.Curve) ([]*zkproofs.DecProof, error) {
	return zkproofs.ProofArrayFromBytes[*zkproofs.DecProof](ec, m.GetProofNu())
}

func NewSignRound3Message(
	from *tss.PartyID,
	delta *big.Int,
	d *big.Int,
	proof []*zkproofs.DecProof,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	pP := zkproofs.ProofArrayToBytes(proof)
	content := &SignRound3Message{
		Delta: delta.Bytes(),
		D:     d.Bytes(),
		Proof: pP[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound3Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.GetDelta()) &&
		common.NonEmptyBytes(m.GetD())
}

func (m *SignRound3Message) UnmarshalDelta() *big.Int {
	return new(big.Int).SetBytes(m.GetDelta())
}

func (m *SignRound3Message) UnmarshalD() *big.Int {
	return new(big.Int).SetBytes(m.GetD())
}

func (m *SignRound3Message) UnmarshalProof(ec elliptic.Curve) ([]*zkproofs.DecProof, error) {
	return zkproofs.ProofArrayFromBytes[*zkproofs.DecProof](ec, m.GetProof())
}

func NewSignRound4Message(
	from *tss.PartyID,
	Gamma *crypto.ECPoint,
	proof []*zkproofs.LogStarProof,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	pP := zkproofs.ProofArrayToBytes(proof)
	pGamma := [][]byte{Gamma.X().Bytes(), Gamma.Y().Bytes()}
	content := &SignRound4Message{
		Gamma: pGamma[:],
		Proof: pP[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound4Message) ValidateBasic() bool {
	return m != nil
}

func (m *SignRound4Message) UnmarshalGamma(ec elliptic.Curve) (*crypto.ECPoint, error) {
	bzs := m.GetGamma()
	Gamma, err := crypto.NewECPoint(
		ec,
		new(big.Int).SetBytes(bzs[0]),
		new(big.Int).SetBytes(bzs[1]),
	)
	if err != nil {
		return Gamma, err
	}
	return Gamma, nil
}

func (m *SignRound4Message) UnmarshalProof(ec elliptic.Curve) ([]*zkproofs.LogStarProof, error) {
	return zkproofs.ProofArrayFromBytes[*zkproofs.LogStarProof](ec, m.GetProof())
}

func NewSignRound5Message(
	from *tss.PartyID,
	s *big.Int,
	proof []*zkproofs.DecProof,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	pP := zkproofs.ProofArrayToBytes(proof)
	content := &SignRound5Message{
		S:     s.Bytes(),
		Proof: pP[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound5Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.GetS())
}

func (m *SignRound5Message) UnmarshalS() *big.Int {
	return new(big.Int).SetBytes(m.GetS())
}

func (m *SignRound5Message) UnmarshalProof(ec elliptic.Curve) ([]*zkproofs.DecProof, error) {
	return zkproofs.ProofArrayFromBytes[*zkproofs.DecProof](ec, m.GetProof())
}
