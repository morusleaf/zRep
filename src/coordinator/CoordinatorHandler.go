package coordinator


import (
	"net"
	"encoding/gob"
	"../proto"
	"fmt"

	"bytes"
	"../util"
	"strings"
	"strconv"
	"time"
	"github.com/dedis/crypto/abstract"
	// "../primitive/fujiokam"
)

var anonCoordinator *Coordinator
var srcAddr *net.UDPAddr


// Handle Use tmpCoordinator to handle data sent from addr.
// The data is stored at buf[:n]
func Handle(buf []byte,addr *net.UDPAddr, tmpCoordinator *Coordinator, n int) {
	// decode the whole message
	anonCoordinator = tmpCoordinator
	srcAddr = addr

	event := &proto.Event{}
	err := gob.NewDecoder(bytes.NewReader(buf[:n])).Decode(event)
	util.CheckErr(err)
	switch event.EventType {
	case proto.SERVER_REGISTER:
		handleServerRegister()
		break
	case proto.CLIENT_REGISTER_CONTROLLERSIDE:
		handleClientRegisterControllerSide(event.Params,);
		break
	case proto.CLIENT_REGISTER_SERVERSIDE:
		handleClientRegisterServerSide(event.Params);
		break
	case proto.MESSAGE:
		handleMsg(event.Params)
		break
	case proto.VOTE:
		handleVote(event.Params)
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
	if len(params["keys"].([]byte)) == 0 {
		// suggest there is no client
		anonCoordinator.Status = MESSAGE
		return
	}
	var g = anonCoordinator.Suite.Point()
	byteG := params["g"].([]byte)
	err := g.UnmarshalBinary(byteG)
	util.CheckErr(err)

	//construct Decrypted reputation map
	keyList := util.ProtobufDecodePointList(params["keys"].([]byte))
	valList := util.ProtobufDecodePointList(params["vals"].([]byte))
	anonCoordinator.DecryptedReputationMap = make(map[string]abstract.Point)
	anonCoordinator.DecryptedKeysMap = make(map[string]abstract.Point)

	for i := 0; i < len(keyList); i++ {
		anonCoordinator.AddIntoDecryptedMap(keyList[i], valList[i])
	}

	// distribute g and hash table of ids to user
	pm := map[string]interface{}{
		"g": params["g"].([]byte),
	}

	event := &proto.Event{EventType:proto.ANNOUNCEMENT, Params:pm}
	for _,addr := range anonCoordinator.Clients {
		util.Send(anonCoordinator.Socket, addr, util.Encode(event))
	}

	// set controller's new g
	anonCoordinator.G = g
	anonCoordinator.Status = MESSAGE
}

// handle server register request
func handleServerRegister() {
	fmt.Println("[debug] Receive the registration info from server " + srcAddr.String());
	// send reply to the new server
	lastServer := anonCoordinator.GetLastServer()

	// update next hop for previous server
	if lastServer != nil {
		pm2 := map[string]interface{}{
			"reply": true,
			"next_hop": srcAddr.String(),
		}
		event2 := &proto.Event{EventType:proto.UPDATE_NEXT_HOP, Params:pm2}
		util.Send(anonCoordinator.Socket, lastServer, util.Encode(event2))
	}

	if lastServer == nil {
		lastServer = anonCoordinator.LocalAddr
	}
	pm1 := map[string]interface{}{
		"reply": true,
		"prev_server": lastServer.String(),
	}
	event1 := &proto.Event{EventType:proto.SERVER_REGISTER_REPLY, Params:pm1}
	util.Send(anonCoordinator.Socket,srcAddr,util.Encode(event1))

	anonCoordinator.AddServer(srcAddr);
}

// Handler for REGISTER event
// send the register request to server to do encryption
func handleClientRegisterControllerSide(params map[string]interface{}) {
	// get client's public key
	publicKey := anonCoordinator.Suite.Point()
	publicKey.UnmarshalBinary(params["public_key"].([]byte))
	anonCoordinator.AddClient(publicKey,srcAddr)

	// compute Pedersen commitment
	xInit := anonCoordinator.Suite.Secret().SetInt64(0)
	PComm, _ := anonCoordinator.PedersenBase.Commit(xInit)
	bytePComm, err := PComm.MarshalBinary()
	util.CheckErr(err)

	// send register info to the first server
	firstServer := anonCoordinator.GetFirstServer()
	pm := map[string]interface{}{
		"public_key": params["public_key"],
		"addr": srcAddr.String(),
		"pcomm": bytePComm,
	}
	event := &proto.Event{EventType:proto.CLIENT_REGISTER_SERVERSIDE, Params:pm}
	util.Send(anonCoordinator.Socket,firstServer,util.Encode(event))
}

// handle client register successful event
func handleClientRegisterServerSide(params map[string]interface{}) {
	// get public key from params (it's one-time nym actually)
	var nym = anonCoordinator.Suite.Point()
	byteNym := params["public_key"].([]byte)
	nym.UnmarshalBinary(byteNym)

	// get PComm from params (encrypted by all servers)
	var PComm = anonCoordinator.Suite.Point()
	bytePComm := params["pcomm"].([]byte)
	err := PComm.UnmarshalBinary(bytePComm)
	util.CheckErr(err)

	var addrStr = params["addr"].(string)
	addr,err := net.ResolveUDPAddr("udp",addrStr)
	util.CheckErr(err)
	pm := map[string]interface{}{}
	event := &proto.Event{EventType:proto.CLIENT_REGISTER_CONFIRMATION, Params:pm}
	util.Send(anonCoordinator.Socket,addr,util.Encode(event))

	// instead of sending new client to server, we will send it when finishing this round. Currently we just add it into buffer
	anonCoordinator.AddClientInBuffer(nym, PComm)
}

// verify the msg and broadcast to clients
func handleMsg(params map[string]interface{}) {
	// get info from the request
	text := params["text"].(string)
	byteSig := params["signature"].([]byte)
	nym := anonCoordinator.Suite.Point()
	byteNym := params["nym"].([]byte)
	err := nym.UnmarshalBinary(byteNym)
	util.CheckErr(err)

	fmt.Println("[debug] Receiving msg from " + srcAddr.String() + ": " + text)
	// verify the identification of the client

	byteText := []byte(text)
	err = util.ElGamalVerify(anonCoordinator.Suite, byteText, nym, byteSig, anonCoordinator.G)
	if err != nil {
		fmt.Print("[note]** Fails to verify the message...")
		return
	}
	// add msg log
	msgID := anonCoordinator.AddMsgLog(nym)

	// generate msg to clients
	rep := anonCoordinator.GetReputation(nym)
	byteRep, err := rep.MarshalBinary()
	util.CheckErr(err)
	pm := map[string]interface{}{
		"text" : text,
		"nym" : params["nym"].([]byte),
		"rep" : byteRep,
		"msgID" : msgID,
	}
	event := &proto.Event{EventType:proto.MESSAGE, Params:pm}

	// send to all the clients
	for _,addr := range anonCoordinator.Clients {
		util.Send(anonCoordinator.Socket, addr, util.Encode(event))
	}
	// send confirmation to msg sender
	pmMsg := map[string]interface{}{
		"reply" : true,
	}
	event1 := &proto.Event{EventType:proto.MSG_REPLY, Params:pmMsg}
	util.Send(anonCoordinator.Socket, srcAddr, util.Encode(event1))
}

// verify the vote and reply to client
func handleVote(params map[string]interface{}) {
	// get info from the request
	text := params["text"].(string)
	byteSig := params["signature"].([]byte)
	nym := anonCoordinator.Suite.Point()
	byteNym := params["nym"].([]byte)
	err := nym.UnmarshalBinary(byteNym)
	util.CheckErr(err)

	fmt.Println("[debug] Receiving vote from " + srcAddr.String() + ": " + text)
	// verify the identification of the client

	byteText := []byte(text)
	err = util.ElGamalVerify(anonCoordinator.Suite,byteText,nym,byteSig, anonCoordinator.G)
	var pm map[string]interface{}
	if err != nil {
		fmt.Print("[note]** Fails to verify the vote...")
		pm = map[string]interface{}{
			"reply" : false,
		}
	}else {
		// avoid duplicate vote
		// todo

		// get msg id and vote
		commands := strings.Split(text,";")
		// modify the reputation
		msgID, _ := strconv.Atoi(commands[0])
		// vote, _ := strconv.Atoi(commands[1])
		targetNym := anonCoordinator.MsgLog[msgID-1]

		anonCoordinator.DecryptedReputationMap[targetNym.String()] =
					anonCoordinator.DecryptedReputationMap[targetNym.String()] //+ vote
		// generate reply msg to client
		pm = map[string]interface{}{
			"reply" : true,
		}
	}

	event := &proto.Event{EventType:proto.VOTE_REPLY, Params:pm}
	// send reply to the client
	util.Send(anonCoordinator.Socket,srcAddr,util.Encode(event))
}

// Handler for ROUND_END event
// send user round end notification
func handleRoundEnd(params map[string]interface{}) {
	// review reputation map
	keyList := util.ProtobufDecodePointList(params["keys"].([]byte))
	valList := util.ProtobufDecodePointList(params["vals"].([]byte))
	anonCoordinator.ReputationMap = make(map[string]abstract.Point)
	anonCoordinator.ReputationKeyMap = make(map[string]abstract.Point)
	for i := 0; i < len(keyList); i++ {
		anonCoordinator.ReputationMap[keyList[i].String()] = valList[i]
		anonCoordinator.ReputationKeyMap[keyList[i].String()] = keyList[i]
	}

	// send user round-end message
	pm := map[string]interface{} {}
	event := &proto.Event{EventType:proto.ROUND_END, Params:pm}
	for _,addr := range anonCoordinator.Clients {
		util.Send(anonCoordinator.Socket, addr, util.Encode(event))
	}
	time.Sleep(500 * time.Millisecond)
	anonCoordinator.Status = READY_FOR_NEW_ROUND
}

