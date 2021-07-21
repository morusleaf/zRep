package client

import (
	"fmt"
	"math/big"
	"strconv"
	"zRep/primitive/fujiokam"
	"zRep/proto"
	"zRep/util"
	// "github.com/dedis/crypto/abstract"
)

func Handle(buf []byte, dissentClient *DissentClient) {
	// decode the whole message
	event, _ := util.DecodeEvent(buf)
	switch event.EventType {
	case proto.CLIENT_REGISTER_CONFIRMATION:
		handleRegisterConfirmation(event.Params, dissentClient)
		break
	case proto.INIT_PEDERSEN_R:
		handleInitPedersenR(event.Params, dissentClient)
		break
	case proto.GN_HONESTY_ANSWER:
		handleGnHonestyAnswer(event.Params, dissentClient)
		break
	case proto.ANNOUNCEMENT_FINALIZE:
		handleAnnouncementFinalize(event.Params, dissentClient)
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
	case proto.BCAST_PEDERSEN_RDIFF:
		handleBroadcastPedersenRDiff(event.Params, dissentClient)
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

// handle protocols' configurations
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
	dissentClient.AllGnHonestyProofPublic = util.ProtobufDecodeBigIntList(params["honesty_prf"].([]byte))

	// Pedersen
	// var HT = dissentClient.Suite.Point()
	// byteHT := params["h"].([]byte)
	// err := HT.UnmarshalBinary(byteHT)
	// util.CheckErr(err)
	// dissentClient.PedersenBase.HT = HT

	// send challenge for g1~g6
	fmt.Println("[debug] Received configurations, start challenging...")
	dissentClient.AllGnHonestyChallenge = base.ChallengeAllGnHonesty()
	pm := map[string]interface{}{
		"honesty_chal": util.ProtobufEncodeBoolList(dissentClient.AllGnHonestyChallenge),
	}
	event := &proto.Event{EventType:proto.GN_HONESTY_CHALLENGE, Params:pm}
	util.SendEvent(dissentClient.LocalAddr, dissentClient.CoordinatorAddr, event)
}

func handleInitPedersenR(params map[string]interface{}, dissentClient *DissentClient) {
	dissentClient.R = util.DecodeSecret(dissentClient.Suite, params["r"].([]byte))
	dissentClient.G = util.DecodePoint(dissentClient.Suite, params["g"].([]byte))
	dissentClient.OnetimePseudoNym = dissentClient.Suite.Point().Mul(dissentClient.G, dissentClient.PrivateKey)
}

// check if protocol's parameters are chosen honestly
func handleGnHonestyAnswer(params map[string]interface{}, dissentClient *DissentClient) {
	base := dissentClient.FujiOkamBase
	answer := util.ProtobufDecodeBigIntList(params["honesty_ans"].([]byte))
	fmt.Println("[debug] Received answer, start checking...")
	res := base.CheckAllGnHonesty(answer, dissentClient.AllGnHonestyChallenge, dissentClient.AllGnHonestyProofPublic)
	if res != 0 {
		panic("Honesty checking failed")
	}
	fmt.Println("[debug] Parameters g1~g6 passed honesty test.")
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

func handleBroadcastPedersenRDiff(params map[string]interface{}, dissentClient *DissentClient) {
	keyList := util.ProtobufDecodePointList(params["keys"].([]byte))
	rDiffs := util.ProtobufDecodeSecretList(params["rDiffs"].([]byte))
	index := util.FindIndexWithinKeyList(keyList, dissentClient.OnetimePseudoNym)
	if index < 0 {
		// client has not participated in this round
		return
	}
	rDiff := rDiffs[index]
	dissentClient.R.Add(dissentClient.R, rDiff)
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
func handleAnnouncementFinalize(params map[string]interface{}, dissentClient *DissentClient) {
	// set One-time pseudonym and g
	g := dissentClient.Suite.Point()
	// deserialize g and calculate nym
	g.UnmarshalBinary(params["g"].([]byte))
	nym := dissentClient.Suite.Point().Mul(g, dissentClient.PrivateKey)

	// update PComm
	keyList := util.ProtobufDecodePointList(params["keys"].([]byte))
	valList := util.ProtobufDecodePointList(params["vals"].([]byte))
	index := util.FindIndexWithinKeyList(keyList, nym)
	if index < 0 {
		panic("Can not find my nym from keyList")
	}
	dissentClient.Index = index
	dissentClient.PCommr = valList[index]

	// set client's parameters
	dissentClient.Status = MESSAGE
	dissentClient.G = g
	dissentClient.OnetimePseudoNym = nym
	dissentClient.AllClientsPublicKeys = keyList

	// update GT & HT
	GT := util.DecodePoint(dissentClient.Suite, params["GT"].([]byte))
	HT := util.DecodePoint(dissentClient.Suite, params["HT"].([]byte))
	dissentClient.PedersenBase.GT = GT
	dissentClient.PedersenBase.HT = HT

	// print out the msg to suggest user to send msg or vote
	fmt.Println("[client] One-Time pseudonym for this round is ");
	fmt.Println(nym);
	fmt.Println("[client] My reputation is", dissentClient.Reputation)
	fmt.Println("[client] Messaging Phase begins.(post <addr> | get <indicator>)");
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