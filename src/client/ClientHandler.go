package client
import (
	"net"
	"encoding/gob"
	"../proto"
	"fmt"
	"../util"
	"bytes"
	"strconv"
	"math/big"
	"../primitive/fujiokam"
	// "github.com/dedis/crypto/abstract"
)

func Handle(buf []byte,addr *net.UDPAddr, dissentClient *DissentClient, n int) {
	// decode the whole message
	event := &proto.Event{}
	err := gob.NewDecoder(bytes.NewReader(buf[:n])).Decode(event)
	util.CheckErr(err)
	switch event.EventType {
	case proto.CLIENT_REGISTER_CONFIRMATION:
		handleRegisterConfirmation(event.Params, dissentClient);
		break
	case proto.ANNOUNCEMENT:
		handleAnnouncement(event.Params, dissentClient);
		break
	case proto.MESSAGE:
		handleMsg(event.Params, dissentClient)
		break
	case proto.VOTE:
		handleVotePhaseStart(dissentClient)
		break
	case proto.ROUND_END:
		handleRoundEnd(event.Params, dissentClient)
		break
	case proto.VOTE_REPLY:
		handleVoteReply(event.Params)
		break
	case proto.MSG_REPLY:
		handleMsgReply(event.Params)
		break;
	default:
		fmt.Println("Unrecognized request")
		break
	}

}


// print out register success info
func handleRegisterConfirmation(params map[string]interface{}, dissentClient *DissentClient) {
	dissentClient.Status = CONNECTED

	// Fujisaki-Okamoto
	N := new(big.Int).SetBytes(params["n"].([]byte))
	base := fujiokam.CreateMinimumBase(dissentClient.Suite, N)
	base.G1 = base.Point().FromBinary(params["g1"].([]byte))
	base.G2 = base.Point().FromBinary(params["g2"].([]byte))
	base.G3 = base.Point().FromBinary(params["g3"].([]byte))
	base.G4 = base.Point().FromBinary(params["g4"].([]byte))
	base.G5 = base.Point().FromBinary(params["g5"].([]byte))
	base.G6 = base.Point().FromBinary(params["g6"].([]byte))
	base.H1 = base.Point().FromBinary(params["h1"].([]byte))
	dissentClient.FujiOkamBase = base

	// Pedersen
	var H = dissentClient.Suite.Point()
	byteH := params["h"].([]byte)
	err := H.UnmarshalBinary(byteH)
	util.CheckErr(err)
	dissentClient.PedersenBase.H = H

	// simply print out register success info here
	fmt.Println("[client] Register success. Waiting for new round begin...");
}

// handle vote start event
func handleVotePhaseStart(dissentClient *DissentClient) {
	if dissentClient.Status != MESSAGE {
		return
	}
	fmt.Println()
	// print out info in client side
	fmt.Println("[client] Voting Phase begins.(cmd: vote <msg_id> (+-)1)")
	fmt.Print("cmd >> ")
}

// reset the status and prepare for the new round
func handleRoundEnd(params map[string]interface{}, dissentClient *DissentClient) {
	dissentClient.Status = CONNECTED

	keyList := util.ProtobufDecodePointList(params["keys"].([]byte))
	diffList:= util.DecodeIntArray(params["diffs"].([]byte))
	myDiff := util.FindIntUsingKeyList(keyList, diffList, dissentClient.OnetimePseudoNym)
	dissentClient.Reputation += myDiff
	fmt.Println("my new reputation:", dissentClient.Reputation)

	fmt.Println()
	fmt.Println("[client] Round ended. Waiting for new round start...");
}

// handle vote reply
func handleVoteReply(params map[string]interface{}) {
	status := params["reply"].(bool)
	if status == true {
		fmt.Println("[client] Voting success!");
		fmt.Print("cmd >> ")
	}else {
		fmt.Println("[client] Failure. Duplicate vote or verification fails!");
	}
}

// handle vote reply
func handleMsgReply(params map[string]interface{}) {
	status := params["reply"].(bool)
	if status == true {
		fmt.Println("[client] Messaging success!");
		fmt.Print("cmd >> ")
	}else {
		fmt.Println("[client] Fails to send message!");
	}
}

// set one-time pseudonym and g, and print out info
func handleAnnouncement(params map[string]interface{}, dissentClient *DissentClient) {
	// set One-time pseudonym and g
	g := dissentClient.Suite.Point()
	// deserialize g and calculate nym
	g.UnmarshalBinary(params["g"].([]byte))
	nym := dissentClient.Suite.Point().Mul(g,dissentClient.PrivateKey)

	// update PComm
	keyList := util.ProtobufDecodePointList(params["keys"].([]byte))
	valList := util.ProtobufDecodePointList(params["vals"].([]byte))
	EList := util.ProtobufDecodeSecretList(params["Es"].([]byte))
	dissentClient.PCommr, dissentClient.E = util.FindCommUsingKeyList(keyList, valList, EList, nym)
	if dissentClient.PCommr == nil {
		panic(1)
	}

	// set client's parameters
	dissentClient.Status = MESSAGE
	dissentClient.G = g
	dissentClient.OnetimePseudoNym = nym

	// print out the msg to suggest user to send msg or vote
	fmt.Println("[client] One-Time pseudonym for this round is ");
	fmt.Println(nym);
	fmt.Println("[client] My reputation is", dissentClient.Reputation)
	fmt.Println("[client] Messaging Phase begins.(msg <indicator> <msg_text>)");
	fmt.Print("cmd >> ");
}

// receive the One-time pseudonym, reputation, and msg from server side
func handleMsg(params map[string]interface{}, dissentClient *DissentClient) {
	// get the reputation
	// byteRep := params["rep"].([]byte)
	// rep := dissentClient.Suite.Point()
	// err := rep.UnmarshalBinary(byteRep)
	// util.CheckErr(err)
	// get One-time pseudonym
	byteNym := params["nym"].([]byte)
	nym := dissentClient.Suite.Point()
	err := nym.UnmarshalBinary(byteNym)
	util.CheckErr(err)
	// get msg text
	text := params["text"].(string)
	// get msg id
	msgID := params["msgID"].(int)
	// don't print for sender
	if(dissentClient.OnetimePseudoNym.Equal(nym)) {
		return
	}
	// print out message in client side
	fmt.Println()
	fmt.Println("Message from ", nym)
	// fmt.Println("Reputation commitment: ", rep);
	fmt.Println("Message ID: " + strconv.Itoa(msgID));
	fmt.Println("Message Text: " + text);
	fmt.Println();
	fmt.Print("cmd >> ")
}