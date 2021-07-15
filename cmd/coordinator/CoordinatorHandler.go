package coordinator

import (
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
	"time"

	"zRep/primitive/lrs"
	"zRep/primitive/pedersen_fujiokam"
	"zRep/proto"
	"zRep/util"
	"zRep/cmd/bridge"

	"github.com/dedis/crypto/abstract"
)

var anonCoordinator *Coordinator


// Handle Use tmpCoordinator to handle data sent from addr.
// The data is stored at buf
func Handle(buf []byte, tmpCoordinator *Coordinator) {
	// decode the whole message
	anonCoordinator = tmpCoordinator
	event, addr := util.DecodeEvent(buf)

	switch event.EventType {
	case proto.SERVER_REGISTER:
		handleServerRegister(addr)
		break
	case proto.UPDATE_PEDERSEN_H:
		handleUpdatePedersenH(event.Params)
		break
	case proto.CLIENT_REGISTER_CONTROLLERSIDE:
		handleClientRegisterControllerSide(event.Params, addr)
		break
	case proto.CLIENT_REGISTER_SERVERSIDE:
		handleClientRegisterServerSide(event.Params);
		break
	case proto.GN_HONESTY_CHALLENGE:
		handleGnHonestyChallenge(event.Params, addr)
		break
	case proto.POST_BRIDGE:
		handlePostBridge(event.Params, addr)
		break
	case proto.REQUEST_BRIDGES:
		handleRequestBridges(event.Params, addr)
		break
	case proto.MESSAGE:
		handleMsg(event.Params, addr)
		break
	case proto.VOTE:
		handleVote(event.Params, addr)
		break
	case proto.ROUND_END:
		handleRoundEnd(event.Params)
		break
	case proto.ANNOUNCEMENT:
		handleAnnouncement(event.Params)
		break
	default:
		fmt.Println("[fatal] Unrecognized request...")
		break
	}
}


// Handler for ANNOUNCEMENT event
// finish announcement and send start message signal to the clients
func handleAnnouncement(params map[string]interface{}) {
	// This event is triggered when server finishes announcement
	// distribute final reputation map to servers
	// if len(params["keys"].([]byte)) == 0 {
	// 	// suggest there is no client
	// 	anonCoordinator.Status = MESSAGE
	// 	return
	// }
	g := util.DecodePoint(anonCoordinator.Suite, params["g"].([]byte))
	anonCoordinator.LRSBase = lrs.CreateBase(util.PointToBigInt(g))

	// update GT & HT
	GT := util.DecodePoint(anonCoordinator.Suite, params["GT"].([]byte))
	HT := util.DecodePoint(anonCoordinator.Suite, params["HT"].([]byte))
	anonCoordinator.PedersenBase.GT = GT
	anonCoordinator.PedersenBase.HT = HT

	//construct Decrypted reputation map
	keyList := util.ProtobufDecodePointList(params["keys"].([]byte))
	valList := util.ProtobufDecodePointList(params["vals"].([]byte))
	anonCoordinator.EndingCommMap = make(map[string]abstract.Point)
	anonCoordinator.EndingKeyMap = make(map[string]abstract.Point)
	anonCoordinator.ReputationDiffMap = make(map[string]int)
	anonCoordinator.AllClientsPublicKeys = keyList

	for i := 0; i < len(keyList); i++ {
		anonCoordinator.AddIntoEndingMap(keyList[i], valList[i])
	}

	// distribute g and table to clients
	pm := map[string]interface{}{
		"g": params["g"].([]byte),
		"keys": params["keys"].([]byte),
		"vals": params["vals"].([]byte),
		"GT": params["GT"].([]byte),
		"HT": params["HT"].([]byte),
	}
	event := &proto.Event{EventType:proto.ANNOUNCEMENT_FINALIZE, Params:pm}
	for _,addr := range anonCoordinator.Clients {
		util.SendEvent(anonCoordinator.LocalAddr, addr, event)
	}

	// distribute g adn table to servers
	// event = &proto.Event{EventType:proto.ANNOUNCEMENT_FINALIZE, Params:pm}
	for _,addr := range anonCoordinator.ServerList {
		util.SendEvent(anonCoordinator.LocalAddr, addr, event)
	}

	// set controller's new g
	anonCoordinator.G = g
	anonCoordinator.Status = MESSAGE
}

// handle server register request
func handleServerRegister(addr *net.TCPAddr) {
	fmt.Println("[debug] Receive the registration info from server " + addr.String());
	lastServer := anonCoordinator.GetLastServer()

	// link new server to the next_hop of last server
	if lastServer != nil {
		pm2 := map[string]interface{}{
			"reply": true,
			"next_hop": addr.String(),
		}
		event2 := &proto.Event{EventType:proto.UPDATE_NEXT_HOP, Params:pm2}
		util.SendEvent(anonCoordinator.LocalAddr, lastServer, event2)
	}

	if lastServer == nil {
		lastServer = anonCoordinator.LocalAddr
	}
	byteH, err := anonCoordinator.PedersenBase.HT.MarshalBinary()
	util.CheckErr(err)
	// tell new server its prev_server is last server
	pm1 := map[string]interface{}{
		"reply": true,
		"prev_server": lastServer.String(),
		"h": byteH,
	}
	event1 := &proto.Event{EventType:proto.SERVER_REGISTER_REPLY, Params:pm1}
	util.SendEvent(anonCoordinator.LocalAddr, addr, event1)

	anonCoordinator.AddServer(addr);
}

func handleUpdatePedersenH(params map[string]interface{}) {
	err := anonCoordinator.PedersenBase.HT.UnmarshalBinary(params["h"].([]byte))
	util.CheckErr(err)
}

// Handler for REGISTER event
// send the register request to server to do encryption
func handleClientRegisterControllerSide(params map[string]interface{}, addr *net.TCPAddr) {
	// get client's public key
	publicKey := anonCoordinator.Suite.Point()
	publicKey.UnmarshalBinary(params["public_key"].([]byte))
	anonCoordinator.AddClient(publicKey, addr)

	// compute Pedersen commitment
	xInit := anonCoordinator.Suite.Secret().SetInt64(int64(bridge.StartingCredit))
	PComm, r := anonCoordinator.PedersenBase.Commit(xInit)
	byteR, err := r.MarshalBinary()
	util.CheckErr(err)

	// send register info to the first server
	firstServer := anonCoordinator.GetFirstServer()
	pm := map[string]interface{}{
		"public_key": params["public_key"],
		"addr": addr.String(),
		"pcomm": util.EncodePoint(PComm),
	}
	event := &proto.Event{EventType:proto.CLIENT_REGISTER_SERVERSIDE, Params:pm}
	util.SendEvent(anonCoordinator.LocalAddr, firstServer, event)

	// send initial r to client
	pm = map[string]interface{}{
		"r": byteR,
		"g": util.EncodePoint(anonCoordinator.G),
	}
	event = &proto.Event{EventType:proto.INIT_PEDERSEN_R, Params:pm}
	util.SendEvent(anonCoordinator.LocalAddr, addr, event)
}

// handle client register successful event
func handleClientRegisterServerSide(params map[string]interface{}) {
	// get public key from params (it's one-time nym actually)
	var nym = anonCoordinator.Suite.Point()
	byteNym := params["public_key"].([]byte)
	nym.UnmarshalBinary(byteNym)

	// get PComm
	var PComm = anonCoordinator.Suite.Point()
	err := PComm.UnmarshalBinary(params["pcomm"].([]byte))
	util.CheckErr(err)

	// encode h from Pedersen Commitment base
	// byteHT, err := anonCoordinator.PedersenBase.HT.MarshalBinary()
	// util.CheckErr(err)

	// send protocol configuration to client
	var addrStr = params["addr"].(string)
	addr, err := net.ResolveTCPAddr("tcp", addrStr)
	util.CheckErr(err)
	fujiokamBase := anonCoordinator.FujiOkamBase
	pm := map[string]interface{}{
		"n": fujiokamBase.N.Bytes(),
		"g1": fujiokamBase.G1.ToBinary(),
		"g2": fujiokamBase.G2.ToBinary(),
		"g3": fujiokamBase.G3.ToBinary(),
		"g4": fujiokamBase.G4.ToBinary(),
		"g5": fujiokamBase.G5.ToBinary(),
		"g6": fujiokamBase.G6.ToBinary(),
		"h1": fujiokamBase.H1.ToBinary(),
		"honesty_prf": util.ProtobufEncodeBigIntList(anonCoordinator.AllGnHonestyProofPublic),
		// "h": byteHT,
	}
	event := &proto.Event{EventType:proto.CLIENT_REGISTER_CONFIRMATION, Params:pm}
	util.SendEvent(anonCoordinator.LocalAddr, addr, event)

	// instead of sending new client to server, we will send it when finishing this round. Currently we just add it into buffer
	anonCoordinator.AddClientInBuffer(nym, PComm)
}

func handleGnHonestyChallenge(params map[string]interface{}, senderAddr *net.TCPAddr) {
	challenge := util.ProtobufDecodeBoolList(params["honesty_chal"].([]byte))
	fmt.Println("[debug] Received challenge, start answering...")
	base := anonCoordinator.FujiOkamBase
	answer := base.AnswerAllGnHonesty(challenge, anonCoordinator.AllGnHonestyProofSecret, anonCoordinator.AllGnHonestyProofPublic)

	pm := map[string]interface{}{
		"honesty_ans": util.ProtobufEncodeBigIntList(answer),
	}
	event := &proto.Event{EventType:proto.GN_HONESTY_ANSWER, Params:pm}
	util.SendEvent(anonCoordinator.LocalAddr, senderAddr, event)
}
// verify the posting message and record the bridge
func handlePostBridge(params map[string]interface{}, senderAddr *net.TCPAddr) {
	// get info from the request
	bridgeAddr := params["bridge_addr"].(string)
	byteSig := params["signature"].([]byte)
	nym := anonCoordinator.Suite.Point()
	byteNym := params["nym"].([]byte)
	err := nym.UnmarshalBinary(byteNym)
	util.CheckErr(err)

	fmt.Println("[debug] Receiving post from " + senderAddr.String() + ": " + bridgeAddr)

	// verify the signature
	byteMsg := bridge.MessageOfPostBridge(params)
	err = util.ElGamalVerify(anonCoordinator.Suite, byteMsg, nym, byteSig, anonCoordinator.G)
	if err != nil {
		fmt.Print("[note]** Fails to verify the message...")
		return
	}

	// record the bridge
	// Note: we assume the client does not provide duplicated bridges
	anonCoordinator.AddBridge(bridgeAddr, nym)
	fmt.Println("[debug] Finished adding bridge " + bridgeAddr)
}

// allocate bridges and ask all servers' signatures
func handleRequestBridges(params map[string]interface{}, senderAddr *net.TCPAddr) {
	// get info from the request
	ind := params["ind"].(int)
	byteSig := params["signature"].([]byte)
	nymR := anonCoordinator.Suite.Point()
	byteNymR := params["nym"].([]byte)
	err := nymR.UnmarshalBinary(byteNymR)
	util.CheckErr(err)
	PCommr := anonCoordinator.EndingCommMap[nymR.String()]

	fmt.Println("[debug] Receiving reqeust from " + senderAddr.String() + ": " + strconv.Itoa(ind))

	// verify the signature
	byteMsg := bridge.MessageOfRequestBridges(params)
	err = util.ElGamalVerify(anonCoordinator.Suite, byteMsg, nymR, byteSig, anonCoordinator.G)
	if err != nil {
		fmt.Print("[note]** Fails to verify the message...")
		return
	}
	fmt.Println("[debug] Signature check passed")

	bridge.VerifyInd(params, PCommr, anonCoordinator.Suite, anonCoordinator.PedersenBase, anonCoordinator.FujiOkamBase)

	// create assignment tuples from unused bridges
	assignments := anonCoordinator.AssignBridges(ind, nymR)

	fmt.Println(assignments)

	pm := map[string]interface{}{
		"assignments" : assignments,
		"ind": ind,
		"nym" : params["nym"].([]byte),
		"FOCommd": params["FOCommd"].([]byte),
		"PCommd": params["PCommd"].([]byte),
		"PCommind": params["PCommind"].([]byte),
		"rind": params["rind"].([]byte),
		"arg_nonneg": params["arg_nonneg"].([]byte),
		"arg_equal": params["arg_equal"].([]byte),
	}
	event := &proto.Event{EventType:proto.SIGN_ASSIGNMENTS, Params:pm}
	// send to all the servers
	for _,addr := range anonCoordinator.ServerList {
		fmt.Println(addr)
		util.SendEvent(anonCoordinator.LocalAddr, addr, event)
	}
}

// verify the msg and broadcast to clients
func handleMsg(params map[string]interface{}, addr *net.TCPAddr) {
	// get info from the request
	text := params["text"].(string)
	byteSig := params["signature"].([]byte)
	nym := anonCoordinator.Suite.Point()
	byteNym := params["nym"].([]byte)
	err := nym.UnmarshalBinary(byteNym)
	util.CheckErr(err)

	fmt.Println("[debug] Receiving msg from " + addr.String() + ": " + text)

	// verify the identification of the client
	byteText := []byte(text)
	err = util.ElGamalVerify(anonCoordinator.Suite, byteText, nym, byteSig, anonCoordinator.G)
	if err != nil {
		fmt.Print("[note]** Fails to verify the message...")
		return
	}

	// PComm for d
	PCommind := anonCoordinator.Suite.Point()
	err = PCommind.UnmarshalBinary(params["PCommind"].([]byte))
	util.CheckErr(err)
	PCommd := anonCoordinator.Suite.Point()
	err = PCommd.UnmarshalBinary(params["PCommd"].([]byte))
	util.CheckErr(err)
	pedersenBase := anonCoordinator.PedersenBase
	PCommr := anonCoordinator.EndingCommMap[nym.String()]
	myPCommd := pedersenBase.Sub(PCommr, PCommind)
	if !PCommd.Equal(myPCommd) {
		fmt.Println("[note]** PCommd != PCoomind^-1 * PCommr (mod p)")
		return
	}
	fmt.Println("[debug] PComm check passed")

	// FOComm for d
	fujiokamBase := anonCoordinator.FujiOkamBase
	FOCommdV := new(big.Int).SetBytes(params["FOCommd"].([]byte))
	ARGnonneg := util.DecodeARGnonneg(params["arg_nonneg"].([]byte))
	FOCommd := fujiokamBase.Point().SetBigInt(FOCommdV)
	if res := fujiokamBase.VerifyNonneg(FOCommd, ARGnonneg); res != true {
		fmt.Println("[note]** Non-negative verification failed")
		return
	}
	fmt.Println("[debug] Non-negative check passed")

	// POComm for d
	ARGequal := util.DecodeARGequal(params["arg_equal"].([]byte))
	if res := pedersen_fujiokam.VerifyEqual(pedersenBase, fujiokamBase, PCommd, FOCommd, ARGequal); res != true {
		fmt.Println("[note]** Equality verification failed")
		return
	}
	fmt.Println("[debug] Equality check passed")


	// add msg log
	msgID := anonCoordinator.AddMsgLog(nym)

	// generate msg to clients
	// rep := anonCoordinator.GetReputation(nym)
	// byteRep, err := rep.MarshalBinary()
	// util.CheckErr(err)
	pm := map[string]interface{}{
		"text" : text,
		"nym" : params["nym"].([]byte),
		// "rep" : byteRep,
		"msgID" : msgID,
	}
	event := &proto.Event{EventType:proto.MESSAGE, Params:pm}

	// send to all the clients
	for _,addr := range anonCoordinator.Clients {
		util.SendEvent(anonCoordinator.LocalAddr, addr, event)
	}
	// send confirmation to msg sender
	pmMsg := map[string]interface{}{
		"reply" : true,
	}
	event1 := &proto.Event{EventType:proto.MSG_REPLY, Params:pmMsg}
	util.SendEvent(anonCoordinator.LocalAddr, addr, event1)
}

// verify the vote and reply to client
func handleVote(params map[string]interface{}, addr *net.TCPAddr) {
	// get info from the request
	text := params["text"].(string)
	byteSig := params["signature"].([]byte)
	nym := anonCoordinator.Suite.Point()
	byteNym := params["nym"].([]byte)
	err := nym.UnmarshalBinary(byteNym)
	util.CheckErr(err)
	// get msg id and vote
	commands := strings.Split(text,";")
	// modify the reputation
	msgID, _ := strconv.Atoi(commands[0])
	vote, _ := strconv.Atoi(commands[1])

	fmt.Println("[debug] Receiving vote from " + addr.String() + ": " + text)

	// verify the identification of the client
	index := util.FindIndexWithinKeyList(anonCoordinator.AllClientsPublicKeys, nym)
	if index < 0 {
		fmt.Println("[note] Can not find nym within keyList")
		return
	}
	sig := lrs.ProtobufDecodeSignature(byteSig)
	res := anonCoordinator.LRSBase.Verify(util.IntToByte(msgID), len(anonCoordinator.AllClientsPublicKeys), index, sig, anonCoordinator.AllClientsPublicKeys)
	var pm map[string]interface{}
	if res == false {
		fmt.Println("[coordinator]** Fails to verify signature...")
		pm = map[string]interface{}{
			"reply" : false,
		}
	}else if anonCoordinator.IsLinkableRecord(sig.Y0) {
		fmt.Println("[coordinator]** Signature implies duplicate vote...")
		pm = map[string]interface{}{
			"reply" : false,
		}
	}else {
		fmt.Println("[debug] Linkable ring signature verification passed")
		// record vote
		anonCoordinator.AddToVoteRecords(sig.Y0)

		targetNym := anonCoordinator.MsgLog[msgID-1]

		anonCoordinator.ReputationDiffMap[targetNym.String()] += vote
		// generate reply msg to client
		pm = map[string]interface{}{
			"reply" : true,
		}
	}

	event := &proto.Event{EventType:proto.VOTE_REPLY, Params:pm}
	// send reply to the client
	util.SendEvent(anonCoordinator.LocalAddr, addr, event)
}

// Handler for ROUND_END event
// send user round end notification
func handleRoundEnd(params map[string]interface{}) {
	// review reputation map
	keyList := util.ProtobufDecodePointList(params["keys"].([]byte))
	valList := util.ProtobufDecodePointList(params["vals"].([]byte))
	anonCoordinator.BeginningCommMap = make(map[string]abstract.Point)
	anonCoordinator.BeginningKeyMap = make(map[string]abstract.Point)
	for i := 0; i < len(keyList); i++ {
		anonCoordinator.BeginningCommMap[keyList[i].String()] = valList[i]
		anonCoordinator.BeginningKeyMap[keyList[i].String()] = keyList[i]
	}

	// update GT & HT
	GT := util.DecodePoint(anonCoordinator.Suite, params["GT"].([]byte))
	HT := util.DecodePoint(anonCoordinator.Suite, params["HT"].([]byte))
	anonCoordinator.PedersenBase.GT = GT
	anonCoordinator.PedersenBase.HT = HT
	// note: no need to tell clients yet

	size := len(anonCoordinator.ReputationDiffMap)
	keys := make([]abstract.Point,size)
	diffs := make([]int, size)
	i := 0
	for k, v := range anonCoordinator.ReputationDiffMap {
		keys[i] = anonCoordinator.EndingKeyMap[k]
		diffs[i] = v
		i++
	}
	byteKeys := util.ProtobufEncodePointList(keys)
	byteDiffs := util.EncodeIntArray(diffs)
	// send user round-end message
	pm := map[string]interface{} {
		"keys": byteKeys,
		"diffs": byteDiffs,
	}
	event := &proto.Event{EventType:proto.ROUND_END, Params:pm}
	for _, addr := range anonCoordinator.Clients {
		util.SendEvent(anonCoordinator.LocalAddr, addr, event)
	}
	time.Sleep(500 * time.Millisecond)
	anonCoordinator.Status = READY_FOR_NEW_ROUND
}