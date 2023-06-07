package accsigning

import (
	"crypto/elliptic"
	"math/big"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	cmt "github.com/bnb-chain/tss-lib/crypto/commitments"
	"github.com/bnb-chain/tss-lib/crypto/mta"
	"github.com/bnb-chain/tss-lib/crypto/schnorr"
	"github.com/bnb-chain/tss-lib/crypto/zkproofs"
	"github.com/bnb-chain/tss-lib/tss"
)

func NewSignRound1Message1(
	to, from *tss.PartyID,
	cA *big.Int,
	proofAlice *zkproofs.EncProof,
	proofXk *zkproofs.EncProof,
	proofXgamma *zkproofs.EncProof,
	proofXkgamma *zkproofs.MulProof,
	proofXkw *zkproofs.MulStarProof,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}
	pa := proofAlice.Bytes()
	pXk := proofXk.Bytes()
	pXg := proofXgamma.Bytes()
	pXkg := proofXkgamma.Bytes()
	pXkw := proofXkw.Bytes()
	content := &SignRound1Message1{
    	CA:              cA.Bytes(),
    	RangeProofAlice: pa[:],
    	ProofXK:            pXk[:],
    	ProofXGamma:        pXg[:],
    	ProofXKgamma:       pXkg[:],
    	ProofXKw:           pXkw[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound1Message1) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.GetCA()) &&
		common.NonEmptyMultiBytes(m.GetRangeProofAlice(), zkproofs.EncProofParts) &&
		common.NonEmptyMultiBytes(m.GetProofXK(), zkproofs.EncProofParts) &&
		common.NonEmptyMultiBytes(m.GetProofXGamma(), zkproofs.EncProofParts) &&
		common.NonEmptyMultiBytes(m.GetProofXKgamma(), zkproofs.MulProofParts) &&
		common.NonEmptyMultiBytes(m.GetProofXKw(), zkproofs.MulStarProofParts)
}

func (m *SignRound1Message1) UnmarshalCA() *big.Int {
	return new(big.Int).SetBytes(m.GetCA())
}

func (m *SignRound1Message1) UnmarshalRangeProofAlice() (*zkproofs.EncProof, error) {
	return zkproofs.EncProofFromBytes(m.GetRangeProofAlice())
}

func (m *SignRound1Message1) UnmarshalProofXK() (*zkproofs.EncProof, error) {
	return zkproofs.EncProofFromBytes(m.GetProofXK())
}

func (m *SignRound1Message1) UnmarshalProofXGamma() (*zkproofs.EncProof, error) {
	return zkproofs.EncProofFromBytes(m.GetProofXGamma())
}

func (m *SignRound1Message1) UnmarshalProofXKgamma() (*zkproofs.MulProof, error) {
	return zkproofs.MulProofFromBytes(m.GetProofXKgamma())
}

func (m *SignRound1Message1) UnmarshalProofXKw(ec elliptic.Curve) (*zkproofs.MulStarProof, error) {
	return zkproofs.MulStarProofFromBytes(ec, m.GetProofXKw())
}




func NewSignRound1Message2(
	from *tss.PartyID,
	xk, xgamma, xkgamma, xkw *big.Int,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
    content := &SignRound1Message2 {
    	XK:  xk.Bytes(),
    	XGamma: xgamma.Bytes(),
    	XKgamma: xkgamma.Bytes(),
    	XKw: xkw.Bytes(),
    }
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound1Message2) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.GetXK()) &&
		common.NonEmptyBytes(m.GetXGamma()) &&
		common.NonEmptyBytes(m.GetXKgamma()) &&
		common.NonEmptyBytes(m.GetXKw())
}