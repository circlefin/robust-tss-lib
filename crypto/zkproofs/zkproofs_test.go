//  Copyright (c) 2023, Circle Internet Financial, LTD.
//  All rights reserved
//  SPDX-License-Identifier: Apache-2.0
//
package zkproofs_test

import (
	"context"
	"crypto/elliptic"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/crypto/paillier"
	"github.com/bnb-chain/tss-lib/crypto/zkproofs"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/tss"
)

// Using a modulus length of 2048 is recommended in the GG18 spec
const (
	testPaillierKeyLength = 2048
)

var (
	privateKey   *paillier.PrivateKey
	publicKey    *paillier.PublicKey
	ringPedersen *zkproofs.RingPedersenParams
	N2           *big.Int
	ec           elliptic.Curve
	q            *big.Int
	ell          *big.Int
)

func setUp(t *testing.T) {
	if privateKey != nil && publicKey != nil {
		return
	}

	fastSetUp(t)
	// randomSetUp(t)

	N2 = new(big.Int).Mul(publicKey.N, publicKey.N)
	ec = tss.EC()
	q = zkproofs.Q(ec)
	ell = zkproofs.GetEll(ec)
	assert.NotNil(t, ell)
}

func GetSavedKeys(idx int) (sk *paillier.PrivateKey, pk *paillier.PublicKey, rp *zkproofs.RingPedersenParams, err error) {
	fixtures, _, err := keygen.LoadKeygenTestFixtures(idx + 1)
	if err != nil {
		return
	}
	fixture := fixtures[idx]
	rp = &zkproofs.RingPedersenParams{
		N: fixture.NTildei,
		S: fixture.H1i,
		T: fixture.H2i,
	}
	sk = fixture.PaillierSK
	pk = &paillier.PublicKey{N: sk.N}
	return
}

// Uses saved parameters to avoid generating safe primes
func fastSetUp(t *testing.T) {
	var err error
	privateKey, publicKey, ringPedersen, err = GetSavedKeys(0)
	assert.NoError(t, err)
	/*
	   publicKeyN, ok1 := new(big.Int).SetString("27211049382861524644850057157545507542696886590540283960025390159193996788501343652978647565795413982008565913431996740996150441442628733944702911606310903691571174831978514607768100962739415243770641415866218655710179051815000344063594849877339361662232467556777670599391620447880232157696728023180789654354055980387485513943837800831610810270201468735811338984794814302567291122079568572562692128599022723998565741943116658548839311703110344606405359008584742613836461622306058541565090831742275465304058046526496475219627315657137701537667490171279291057554426629328826117016630710430344618021814847926167419603273", 0)
	   publicKeyLambdaN, ok2 := new(big.Int).SetString("13605524691430762322425028578772753771348443295270141980012695079596998394250671826489323782897706991004282956715998370498075220721314366972351455803155451845785587415989257303884050481369707621885320707933109327855089525907500172031797424938669680831116233778388835299695810223940116078848364011590394827176862909456120106820218880749262603495154559321414751104171781311307972528790387817519653543134580951898819422809599550963949859013114409724551654662429310519243171634743954847225963824865505509224024395635532971361061718517023541132785988540904575905696328944519455042537876709836037899593543490981081287633354", 0)
	   publicKeyPhiN, ok3 := new(big.Int).SetString("27211049382861524644850057157545507542696886590540283960025390159193996788501343652978647565795413982008565913431996740996150441442628733944702911606310903691571174831978514607768100962739415243770641415866218655710179051815000344063594849877339361662232467556777670599391620447880232157696728023180789654353725818912240213640437761498525206990309118642829502208343562622615945057580775635039307086269161903797638845619199101927899718026228819449103309324858621038486343269487909694451927649731011018448048791271065942722123437034047082265571977081809151811392657889038910085075753419672075799187086981962162575266708", 0)

	   	if ok1 && ok2 && ok3 {
	   	    publicKey = &paillier.PublicKey{N: publicKeyN}
	   	    privateKey = &paillier.PrivateKey{PublicKey: *publicKey, LambdaN: publicKeyLambdaN, PhiN: publicKeyPhiN}
	   	} else {

	   	    assert.Error(t, errors.New("failed to read paillier parameters"), "failed to recover paillier keys")
	   	}

	   rpN, ok4 := new(big.Int).SetString("21750941670479643325687654945372487646336538910799637393357504716612155676295784773612841484924016032781248268897568896596818629453743456703998837285828425770326361073485440892487038024179490413980827278027826834380230822813120111060539138630878921093466396120278191763337963550659323447680222011883239703510419581603074025512989877167172203888552078143021497532112376120237066640581053833312519692482175862743321097993385706822473206280914471768230199168994041220734918766229585692250605054084127452040522485962337504837581474851210783243700862790253428751086607805191152994121619379147417578689974871317829450894117", 0)
	   rpS, ok5 := new(big.Int).SetString("18207801744659347756664696529736216127183926998814235091494452593790561467101053976397839360541159945326998503888708010957301481759982694942867382853462348980753397313625430344895531688002788809823771420436466817399418077350737331642767177546715990103993220776383523015334407598422461093561622924763609722030899707006788237248956444736661821511010133955049086096988234926085046549707089079599453252550057061617863674232645547237292214288785541620549181443823705425063120706274573221878534557423721843546986319069906226450317305820086641349850576180698668405828027097226596358204893058120820391573772572017077507331481", 0)
	   rpT, ok6 := new(big.Int).SetString("5927681066346589788949835137697555426772276751709799421927162997171687273514253221470977374572228895434841335460712071089351014291497766589858519810105052978232771611290283863369720448340751536098858444536398674302100495490797564396813735856746872932622854810614710920600150497766750603361656170048932900259612584806247886508272354263716579014173784074959362583516731325789796221003236595111948683864126506544784094627039896908632682394207665930363059848454900126680010120543579630581119260065189050969321759894587350245504335742313575784262578339261498660027586762281225826911082686415730298792065830946423850285076", 0)

	   	if ok4 && ok5 && ok6 {
	   	    ringPedersen = &zkproofs.RingPedersenParams{
	   	        N: rpN,
	   	        S: rpS,
	   	        T: rpT,
	   	    }
	   	} else {

	   	    assert.Error(t, errors.New("failed to read ring pedersen parameters"), "failed to recover ring pedersen parameters")
	   	}
	*/
}

func randomSetUp(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	var err error
	privateKey, publicKey, err = paillier.GenerateKeyPair(ctx, testPaillierKeyLength)
	assert.NoError(t, err)

	preParams, err := keygen.GeneratePreParamsWithContext(ctx, 1)
	assert.NotNil(t, preParams, "preParams nil")
	assert.Nil(t, err, "error generating preparams")

	ringPedersen = &zkproofs.RingPedersenParams{
		S: preParams.H1i,
		T: preParams.H2i,
		N: preParams.NTildei,
	}

	ec = tss.EC()
	printParams(t)
}

func printParams(t *testing.T) {
	t.Log("privateKey")
	t.Log("\tpublicKey.N: " + publicKey.N.String())
	t.Log("\tLambdaN: " + privateKey.LambdaN.String())
	t.Log("\tPhiN: " + privateKey.PhiN.String())

	t.Log("ringPedersen")
	t.Log("\tN: " + ringPedersen.N.String())
	t.Log("\tS: " + ringPedersen.S.String())
	t.Log("\tT: " + ringPedersen.T.String())
}

func TestPseudoPaillier(t *testing.T) {
	m := big.NewInt(200)
	x := big.NewInt(385)
	c1, err := publicKey.EncryptWithRandomness(m, x)
	assert.NoError(t, err, "failed to paillier encrypt")

	N := publicKey.N
	NPlusOne := new(big.Int).Add(N, big.NewInt(1))
	c2 := zkproofs.PseudoPaillierEncrypt(NPlusOne, m, x, N, N2)
	if c1.Cmp(c2) != 0 {
		assert.Error(t, errors.New("PseudoPaillierEncrypt failed"), "PseudoPaillierEncrypt failed")
	}
}

func TestAPlusBC(t *testing.T) {
	a := big.NewInt(1000)
	b := big.NewInt(3)
	c := big.NewInt(100)
	actual := zkproofs.APlusBC(a, b, c)
	expected := big.NewInt(1300)
	if expected.Cmp(actual) != 0 {
		assert.Error(t, errors.New("APlusBC failed"), "APlusBC failed")
	}
}

func TestATimesBToTheCModN(t *testing.T) {
	a := big.NewInt(1000)
	b := big.NewInt(2)
	c := big.NewInt(4)
	n := big.NewInt(13)
	actual := zkproofs.ATimesBToTheCModN(a, b, c, n)
	// a * b^c mod 13= 16000 mod 13 = 10
	expected := big.NewInt(10)
	if expected.Cmp(actual) != 0 {
		assert.Error(t, errors.New("ATimesBToTheCModN failed"), "ATimesBToTheCModN failed")
	}
}

func TestRingPedersen(t *testing.T) {
	S := big.NewInt(10)
	T := big.NewInt(2)
	a := big.NewInt(3)
	b := big.NewInt(4)
	n := big.NewInt(13)
	rp := &zkproofs.RingPedersenParams{S: S, T: T, N: n}
	actual := rp.Commit(a, b)
	// s^a t^b mod n = 10^3 2^4 mod 13 = 1016 mod 13 = 2
	expected := big.NewInt(2)
	if expected.Cmp(actual) != 0 {
		assert.Error(t, errors.New("test of rp.Commit failed"), "rp.Commit failed")
	}
}

func TestECCurveProofConstants(t *testing.T) {
	setUp(t)
	p := zkproofs.NewEll(ell)

	expectedEll := big.NewInt(256)
	twoPow256, _ := new(big.Int).SetString("115792089237316195423570985008687907853269984665640564039457584007913129639936", 0)
	expectedTwoPowEll := twoPow256
	expectedEpsilon := big.NewInt(3)
	expectedEllPlusEpsilon := big.NewInt(259)
	eight := big.NewInt(8)
	expectedTwoPowEllPlusEpsilon := new(big.Int).Mul(twoPow256, eight)

	if p.Ell.Cmp(expectedEll) != 0 {
		assert.Error(t, errors.New("bad Ell"), "bad Ell")
	}
	if p.TwoPowEll.Cmp(expectedTwoPowEll) != 0 {
		assert.Error(t, errors.New("bad TwoPowEll"), "bad TwoPowEll")
	}
	if p.Epsilon.Cmp(expectedEpsilon) != 0 {
		assert.Error(t, errors.New("bad Epsilon"), "bad Epsilon")
	}
	if p.EllPlusEpsilon.Cmp(expectedEllPlusEpsilon) != 0 {
		assert.Error(t, errors.New("bad EllPlusEpsilon"), "bad EllPlusEpsilon")
	}
	if p.TwoPowEllPlusEpsilon.Cmp(expectedTwoPowEllPlusEpsilon) != 0 {
		assert.Error(t, errors.New("bad TwoPowEllPlusEpsilon"), "bad TwoPowEllPlusEpsilon")
	}
}
