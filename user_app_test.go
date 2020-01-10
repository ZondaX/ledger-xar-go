/*******************************************************************************
*   (c) 2018 ZondaX GmbH
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

package ledger_xar_go

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

// Ledger Test Mnemonic: equip will roof matter pink blind book anxiety banner elbow sun young

func Test_UserFindLedger(t *testing.T) {
	userApp, err := FindLedgerXARApp()
	if err != nil {
		t.Fatalf(err.Error())
	}

	assert.NotNil(t, userApp)
	defer userApp.Close()
}

func Test_UserGetVersion(t *testing.T) {
	userApp, err := FindLedgerXARApp()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer userApp.Close()

	userApp.api.Logging = true

	version, err := userApp.GetVersion()
	require.Nil(t, err, "Detected error")
	fmt.Println(version)
}

func Test_UserGetPublicKey(t *testing.T) {
	userApp, err := FindLedgerXARApp()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer userApp.Close()

	userApp.api.Logging = true

	path := []uint32{44, 463, 5, 0, 21}

	pubKey, err := userApp.GetPublicKeySECP256K1(path)
	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}

	assert.Equal(t, 33, len(pubKey),
		"Public key has wrong length: %x, expected length: %x\n", pubKey, 65)
	fmt.Printf("PUBLIC KEY: %x\n", pubKey)

	assert.Equal(t,
		"0353e8261cb89ccc43261639292e49fd3db38d5d46590fd715eb53fde252e7941b",
		hex.EncodeToString(pubKey),
		"Unexpected pubkey")
}

func Test_GetAddressPubKeySECP256K1_Zero(t *testing.T) {
	userApp, err := FindLedgerXARApp()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer userApp.Close()

	userApp.api.Logging = true

	hrp := "xar"
	path := []uint32{44, 0x1cf, 0, 0, 0}

	pubKey, addr, err := userApp.GetAddressPubKeySECP256K1(path, hrp)
	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}

	fmt.Printf("PUBLIC KEY : %x\n", pubKey)
	fmt.Printf("BECH32 ADDR: %s\n", addr)

	assert.Equal(t, 33, len(pubKey), "Public key has wrong length: %x, expected length: %x\n", pubKey, 65)

	assert.Equal(t, "03e33e4e79dcd0bbfacf73637172cbfc93a2939a74041e86ed7a8ac31bcd8474b9", hex.EncodeToString(pubKey), "Unexpected pubkey")
	assert.Equal(t, "xar1v8n4etx23j3jsyykmx0mzd73dr47fr494h3ft2", addr, "Unexpected addr")
}

func Test_GetAddressPubKeySECP256K1(t *testing.T) {
	userApp, err := FindLedgerXARApp()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer userApp.Close()

	userApp.api.Logging = true

	hrp := "xar"
	path := []uint32{44, 0x1cf, 5, 0, 21}

	pubKey, addr, err := userApp.GetAddressPubKeySECP256K1(path, hrp)
	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}

	fmt.Printf("PUBLIC KEY : %x\n", pubKey)
	fmt.Printf("BECH32 ADDR: %s\n", addr)

	assert.Equal(t, 33, len(pubKey), "Public key has wrong length: %x, expected length: %x\n", pubKey, 65)

	assert.Equal(t, "0353e8261cb89ccc43261639292e49fd3db38d5d46590fd715eb53fde252e7941b", hex.EncodeToString(pubKey), "Unexpected pubkey")
	assert.Equal(t, "xar1ke235ek9lta603ud6l58xhdgd8s7u9ddtlrndm", addr, "Unexpected addr")
}

func Test_UserPK_HDPaths(t *testing.T) {
	userApp, err := FindLedgerXARApp()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer userApp.Close()

	userApp.api.Logging = true

	path := []uint32{44, 0x1cf, 0, 0, 0}

	expected := []string{
		"03e33e4e79dcd0bbfacf73637172cbfc93a2939a74041e86ed7a8ac31bcd8474b9",
		"037c1a78d950204e2338ff4b590e241c4b4fc9a57583ab575e2cec87c3b5b72023",
		"03e82b4a69891f5badcfe61c34cbc793d08f854336d7703a96e1749a167fded306",
		"03dfbfe232818e20182c47063046f89070919357023cc3ed4d89bf994972b680b9",
		"03bf7170640356ee774ca053d1ae515e60b10da4ec9b5688affd163d1db221e053",
		"02e68a8151530abb77c975f3a772454ebdfbf6e434adf97f0f172773729f823a3e",
		"0376c21fb20fd79599b5de159feb94200342e15564487c6ab6034c2d41e3c7b49b",
		"03b327e59ebd5418ae4fc4ab18135c8576bec7041da964e5285606144692bc7b0e",
		"0273581b27695952cb6b878962a89ed9a0cda17f7ee628a04ab078689508acdb49",
		"028a32ce1c538357d062e49301d84b8a836c67e734ac692fd6a352e1a32ba38fc7",
	}

	for i := uint32(0); i < 10; i++ {
		path[4] = i

		pubKey, err := userApp.GetPublicKeySECP256K1(path)
		if err != nil {
			t.Fatalf("Detected error, err: %s\n", err.Error())
		}

		assert.Equal(
			t,
			33,
			len(pubKey),
			"Public key has wrong length: %x, expected length: %x\n", pubKey, 65)

		assert.Equal(
			t,
			expected[i],
			hex.EncodeToString(pubKey),
			"Public key 44'/463'/0'/0/%d does not match\n", i)

		_, err = btcec.ParsePubKey(pubKey[:], btcec.S256())
		require.Nil(t, err, "Error parsing public key err: %s\n", err)

	}
}

func getDummyTx() []byte {
	dummyTx := `{
		"account_number": 1,
		"chain_id": "some_chain",
		"fee": {
			"amount": [{"amount": 10, "denom": "DEN"}],
			"gas": 5
		},
		"memo": "MEMO",
		"msgs": ["SOMETHING"],
		"sequence": 3
	}`
	dummyTx = strings.Replace(dummyTx, " ", "", -1)
	dummyTx = strings.Replace(dummyTx, "\n", "", -1)
	dummyTx = strings.Replace(dummyTx, "\t", "", -1)

	return []byte(dummyTx)
}

func Test_UserSign(t *testing.T) {
	userApp, err := FindLedgerXARApp()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer userApp.Close()

	userApp.api.Logging = true

	path := []uint32{44, 463, 0, 0, 5}

	message := getDummyTx()
	signature, err := userApp.SignSECP256K1(path, message)
	if err != nil {
		t.Fatalf("[Sign] Error: %s\n", err.Error())
	}

	// Verify Signature
	pubKey, err := userApp.GetPublicKeySECP256K1(path)
	if err != nil {
		t.Fatalf("Detected error, err: %s\n", err.Error())
	}

	if err != nil {
		t.Fatalf("[GetPK] Error: " + err.Error())
		return
	}

	pub2, err := btcec.ParsePubKey(pubKey[:], btcec.S256())
	if err != nil {
		t.Fatalf("[ParsePK] Error: " + err.Error())
		return
	}

	sig2, err := btcec.ParseDERSignature(signature[:], btcec.S256())
	if err != nil {
		t.Fatalf("[ParseSig] Error: " + err.Error())
		return
	}

	hash := sha256.Sum256(message)
	verified := sig2.Verify(hash[:], pub2)
	if !verified {
		t.Fatalf("[VerifySig] Error verifying signature: " + err.Error())
		return
	}
}

func Test_UserSign_Fails(t *testing.T) {
	userApp, err := FindLedgerXARApp()
	if err != nil {
		t.Fatalf(err.Error())
	}
	defer userApp.Close()

	userApp.api.Logging = true

	path := []uint32{44, 463, 0, 0, 5}

	message := getDummyTx()
	garbage := []byte{65}
	message = append(garbage, message...)

	_, err = userApp.SignSECP256K1(path, message)
	assert.Error(t, err)
	errMessage := err.Error()

	if errMessage != "Invalid character in JSON string" && errMessage != "Unexpected characters" {
		assert.Fail(t, "Unexpected error message returned: " + errMessage )
	}
}
