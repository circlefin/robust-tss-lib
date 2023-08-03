package signing

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"runtime"
	"sync/atomic"
	"testing"

	//	"github.com/btcsuite/btcd/btcec"
	//	"github.com/ipfs/go-log"
	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/test"
	"github.com/bnb-chain/tss-lib/tss"
)

func Run(
    t *testing.T,
    keys []keygen.LocalPartySaveData,
    signPIDs tss.SortedPartyIDs,
    p2pCtx *tss.PeerContext,
) *OutStruct {
	threshold := test.TestThreshold
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan common.SignatureData, len(signPIDs))

	updater := test.SharedPartyUpdater

	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold)

		P := NewLocalParty(big.NewInt(42), params, keys[i], outCh, endCh).(*LocalParty)
		parties = append(parties, P)
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	var ended int32
signing:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			//			assert.FailNow(t, err.Error())
			break signing

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					//					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(parties[dest[0].Index], msg, errCh)
			}

		case <-endCh:
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				//				t.Logf("Done. Received signature data from %d participants", ended)
				R := parties[0].temp.bigR
				r := parties[0].temp.rx
				fmt.Printf("sign result: R(%s, %s), r=%s\n", R.X().String(), R.Y().String(), r.String())

				modN := common.ModInt(tss.S256().Params().N)

				// BEGIN check s correctness
				sumS := big.NewInt(0)
				sumK := big.NewInt(0)
				for i, p := range parties {
					sumS = modN.Add(sumS, p.temp.si)
					sumK = modN.Add(sumK, parties[i].temp.k)
				}
				fmt.Printf("S: %s\n", sumS.String())
				// END check s correctness

				// BEGIN ECDSA verify
				pkX, pkY := keys[0].ECDSAPub.X(), keys[0].ECDSAPub.Y()
				pk := ecdsa.PublicKey{
					Curve: tss.EC(),
					X:     pkX,
					Y:     pkY,
				}
				ok := ecdsa.Verify(&pk, big.NewInt(42).Bytes(), R.X(), sumS)
				assert.True(t, ok, "ecdsa verify must pass")
				//				t.Log("ECDSA signing test done.")
				// END ECDSA verify

				party := parties[0]
				si := make([]*big.Int, len(parties))
				ks := make([]*big.Int, len(parties))
				ws := make([]*big.Int, len(parties))
				gammas := make([]*big.Int, len(parties))
				sigmas := make([]*big.Int, len(parties))
				pointGammas :=  make([]*crypto.ECPoint, len(parties))
				for i, _ := range parties {
                    si[i] = parties[i].temp.si
                    ks[i] = parties[i].temp.k
                    ws[i] = parties[i].temp.w
                    gammas[i] = parties[i].temp.gamma
                    sigmas[i] = parties[i].temp.sigma
                    pointGammas[i]= parties[i].temp.pointGamma
				}
				return &OutStruct{
                    K:    sumK,
					M:    party.temp.m,
					Rx:   party.temp.rx,
					Ry:   party.temp.ry,
					SumS: sumS,
					R:    party.temp.bigR,
					PkX:  pkX,
					PkY:  pkY,
					Si:  si,
					Ks: ks,
					Ws: ws,
					Theta: party.temp.theta,
					ThetaInv: party.temp.thetaInverse,
					Gamma: gammas,
					PointGamma: pointGammas,
					Sigma: sigmas,
				}

				break signing
			}
		}
	}
	// t.Logf("done signing.Run()")
	return nil
}

type OutStruct struct {
	K, M, Rx, Ry, SumS, PkX, PkY, Theta, ThetaInv *big.Int
	R               *crypto.ECPoint
	PointGamma []*crypto.ECPoint
	Si, Ks, Ws, Gamma, Sigma              []*big.Int
}
