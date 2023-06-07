package zkproofs_test

import (
    "math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto/zkproofs"
)

func TestEncKnownInputProof(t *testing.T) {
    k, _ := new(big.Int).SetString("114389473239505230491163146795412138983239597318806644445410158725115455132692", 0)
    K, _ := new(big.Int).SetString("465731706496473911847378750369631955920537852546894056438324922002323832557052064091918779928998117741164270297323463208064330285407219572177029360826008098571725648121552938575861312248098147580091443066258128496730130821607283612246459392571020574355259214835267622850399259810669526425866890543731585668563000223903364750259693607987689860689205912013767228001149855306031477483177607033616664945169002738496514270876030965906518470081313910226789131722379851589407879764493910658365838303529011095873089917057785671727758265706395079059011018323942761921652586013265038187227881878435999741578132905577045639379857443750047257615234688808089465285800849341881615220067137051394879797468117924789386876077614815545558385023634752683865402913773342113237762409485419286550203760964443643787231978551910564595235133167072250444545071003504714377320420465772179408459459859448083450614589893581034041705745134325422367038213583684619090512936707235222566271258400064022000366699765004412201467436278215661566566076268380633299387576044688216534173466664307669004872674171324245476404394755604318512835901804601155380746059882379447729445237927082554648890833562174587009270444294220972401968147951439030634576490769491329725523066373", 0)
    rho, _ := new(big.Int).SetString("1589242199014186642803401666691520301635771315788503864752220777217738751901654796434493911079208937341944417070764384236037629531669977085618074891575239323560840983052587886127349018243828507737099166737147980821930538648101089752705183504157416079572589094945765694857956926575398689326240518052796539017352391285840754641810683001857169286294137848743745186617946790757924489281977116077802106464822099774315121788634674603354884106884083707909112735182653869657570449994189127412585926110940250122589069694819774998940166052085553665809474348432193960236312713027489316513952283294330658069074266897280468237987", 0)

    witness := &zkproofs.EncWitness{
        K: k,
        Rho: rho,
    }
	statement := &zkproofs.EncStatement{
	    EC: ec,
	    N0: publicKey.N,
	    K: K,
	}
	proof, err := zkproofs.NewEncProof(witness, statement, ringPedersen)
	assert.NoError(t, err)
	assert.NotNil(t, proof, "proof is nil")
	assert.False(t, proof.Nil(), "proof has nil fields")
	assert.True(t, proof.Verify(statement, ringPedersen), "proof failed to verify")
}

func TestEncProof(t *testing.T) {
	setUp(t)

	// K = Encrypt(N0, k, rho)
	k := common.GetRandomPositiveInt(q)
	K, rho, err := publicKey.EncryptAndReturnRandomness(k)
	assert.NoError(t, err, "encrypt K not error")
    // witness
    witness := &zkproofs.EncWitness{
        K: k,
        Rho: rho,
    }

	statement := &zkproofs.EncStatement{
	    EC: ec,
	    N0: publicKey.N,
	    K: K,
	}

	// Prove that:
	// C = Encrypt(N0, x, rho)
	// k \in +- 2^{ell+epsilon}
	proof, err := zkproofs.NewEncProof(witness, statement, ringPedersen)
	assert.NoError(t, err)
	assert.True(t, proof.Verify(statement, ringPedersen), "proof failed to verify")
}

func TestEncProofBytes(t *testing.T) {
	setUp(t)

	// K = Encrypt(N0, k, rho)
	k := common.GetRandomPositiveInt(q)
	K, rho, err := publicKey.EncryptAndReturnRandomness(k)
	assert.NoError(t, err, "encrypt K not error")
    // witness
    witness := &zkproofs.EncWitness{
        K: k,
        Rho: rho,
    }

	statement := &zkproofs.EncStatement{
	    EC: ec,
	    N0: publicKey.N,
	    K: K,
	}

	// Prove that:
	// C = Encrypt(N0, x, rho)
	// k \in +- 2^{ell+epsilon}
	proof, err := zkproofs.NewEncProof(witness, statement, ringPedersen)
	assert.NoError(t, err)
	assert.NotNil(t, proof)
	assert.True(t, proof.Verify(statement, ringPedersen), "proof failed to verify")

	proofBytes := proof.Bytes()
	var proofInBytes [][]byte = proofBytes[:]
	newProof, err := zkproofs.EncProofFromBytes(proofInBytes)
	assert.NoError(t, err)
	assert.NotNil(t, newProof)
	assert.False(t, newProof.Nil())
	assert.True(t,newProof.Verify(statement, ringPedersen))
}
