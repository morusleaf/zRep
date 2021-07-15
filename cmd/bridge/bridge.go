package bridge

import (
	"bytes"
	"fmt"
	"math/big"
	"log"
	"encoding/gob"

	"reflect"
	"github.com/dedis/crypto/nist"
	"go.dedis.ch/protobuf"

	"github.com/dedis/crypto/abstract"
	"zRep/util"
	"zRep/primitive/pedersen"
	"zRep/primitive/pedersen_fujiokam"
	"zRep/primitive/fujiokam"
)

const StartingCredit int = 5

type Bridge struct {
	Addr string // bridge address
	Nym abstract.Point // bridge provider's nym
}

type Assignment struct {
	NymR abstract.Point // bridge requester's nym
	Addr string
	Nym abstract.Point // bridge provider's nym
}

func VerifyInd(params map[string]interface{}, PCommr abstract.Point, suite abstract.Suite, pedersenBase *pedersen.PedersenBase, fujiokamBase *fujiokam.FujiOkamBase) bool {
	ind := params["ind"].(int)
	nymR := suite.Point()
	byteNymR := params["nym"].([]byte)
	err := nymR.UnmarshalBinary(byteNymR)
	util.CheckErr(err)
	PCommind := suite.Point()
	err = PCommind.UnmarshalBinary(params["PCommind"].([]byte))
	util.CheckErr(err)
	PCommd := suite.Point()
	err = PCommd.UnmarshalBinary(params["PCommd"].([]byte))
	util.CheckErr(err)

	// commit ind by myself then compare
	xind := suite.Secret().SetInt64(int64(ind))
	rind := suite.Secret()
	err = rind.UnmarshalBinary(params["rind"].([]byte))
	util.CheckErr(err)
	myPCommind := pedersenBase.CommitWithR(xind, rind)
	if !myPCommind.Equal(PCommind) {
		fmt.Println("[note]** Re-commitment check failed")
		return false
	}
	fmt.Println("[debug] Re-commitment check passed")

	// PComm for d
	myPCommd := pedersenBase.Sub(PCommr, PCommind)
	if !PCommd.Equal(myPCommd) {
		fmt.Println("[note]** PCommd != PCoomind^-1 * PCommr (mod p)")
		return false
	}
	fmt.Println("[debug] PComm check passed")

	// FOComm for d
	FOCommdV := new(big.Int).SetBytes(params["FOCommd"].([]byte))
	ARGnonneg := util.DecodeARGnonneg(params["arg_nonneg"].([]byte))
	FOCommd := fujiokamBase.Point().SetBigInt(FOCommdV)
	if res := fujiokamBase.VerifyNonneg(FOCommd, ARGnonneg); res != true {
		fmt.Println("[note]** Non-negative check failed")
		return false
	}
	fmt.Println("[debug] Non-negative check passed")

	// POComm for d
	ARGequal := util.DecodeARGequal(params["arg_equal"].([]byte))
	if res := pedersen_fujiokam.VerifyEqual(pedersenBase, fujiokamBase, PCommd, FOCommd, ARGequal); res != true {
		fmt.Println("[note]** Equality check failed")
		return false
	}
	fmt.Println("[debug] Equality check passed")

	return true
}

// ****************************************************************************
// Extract message body from package
// ****************************************************************************

func MessageOfRequestBridges(params map[string]interface{}) []byte {
	ind := params["ind"].(int)
	byteInd := util.IntToByte(ind)
	msg := append(byteInd, params["nym"].([]byte)...)
	msg = append(msg, params["FOCommd"].([]byte)...)
	msg = append(msg, params["PCommd"].([]byte)...)
	msg = append(msg, params["PCommind"].([]byte)...)
	msg = append(msg, params["rind"].([]byte)...)
	msg = append(msg, params["arg_nonneg"].([]byte)...)
	msg = append(msg, params["arg_equal"].([]byte)...)
	return msg
}

func MessageOfPostBridge(params map[string]interface{}) []byte {
	bridgeAddr := params["bridge_addr"].(string)
	msg := append([]byte(bridgeAddr), params["nym"].([]byte)...)
	return msg
}

// ****************************************************************************
// Encoder / Decoder
// ****************************************************************************

type AssignmentList struct {
	Assignments []Assignment
}

func ProtobufEncodeAssignmentList(plist []Assignment) []byte {
	bytes, err := protobuf.Encode(&AssignmentList{plist})
	util.CheckErr(err)
	return bytes
}

func ProtobufDecodeAssignmentList(bytes []byte) []Assignment {
	var aAssignment Assignment
	var tAssignment = reflect.TypeOf(&aAssignment).Elem()
	suite := nist.NewAES128SHA256QR512()
	cons := protobuf.Constructors {
		tAssignment: func()interface{} {
			return Assignment{NymR: suite.Point(), Addr: "", Nym: suite.Point()}
		},
	}

	var msg AssignmentList
	if err := protobuf.DecodeWithConstructors(bytes, &msg, cons); err != nil {
		log.Fatal(err)
	}
	return msg.Assignments
}

func EncodeAssignment(assignment *Assignment) []byte {
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	err := encoder.Encode(assignment)
	util.CheckErr(err)
	return buf.Bytes()
}

func DecodeAssignment(data []byte) *Assignment {
	assignment := new(Assignment)
	buf := bytes.NewReader(data)
	decoder := gob.NewDecoder(buf)
	err := decoder.Decode(assignment)
	util.CheckErr(err)
	return assignment
}