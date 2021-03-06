package server

import (
	"encoding/gob"
	"fmt"
	"math/big"
	"net"
	"zRep/cmd/bridge"
	"zRep/proto"
	"zRep/util"
	"zRep/util/shuffle"
	"zRep/primitive/fujiokam"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/proof"
	"github.com/dedis/crypto/random"
	// "github.com/dedis/crypto/anon"
)

var anonServer *AnonServer

func Handle(buf []byte, tmpServer *AnonServer) {
	// decode the whole message
	byteArr := make([]util.ByteArray, 2)
	gob.Register(byteArr)

	anonServer = tmpServer
	event, addr := util.DecodeEvent(buf)
	switch event.EventType {
	case proto.SERVER_REGISTER_REPLY:
		handleServerRegisterReply(event.Params, addr)
		break
	case proto.ANNOUNCEMENT:
		handleAnnouncement(event.Params)
		break
	case proto.ANNOUNCEMENT_FINALIZE:
		handleAnnouncementFinalize(event.Params)
		break
	case proto.SIGN_ASSIGNMENTS:
		handleSignAssignments(event.Params, addr)
		break
	case proto.UPDATE_NEXT_HOP:
		handleUpdateNextHop(event.Params)
		break
	case proto.CLIENT_REGISTER_SERVERSIDE:
		handleClientRegisterServerSide(event.Params)
		break
	case proto.ROUND_END:
		handleRoundEnd(event.Params)
		break
	case proto.BCAST_PEDERSEN_H:
		handleBroadcastPedersenH(event.Params)
		break
	default:
		fmt.Println("Unrecognized request")
		break
	}
}

func verifyNeffShuffle(params map[string]interface{}) {
	if _, shuffled := params["shuffled"]; shuffled {
		// get all the necessary parameters
		xbarList := util.ProtobufDecodePointList(params["xbar"].([]byte))
		ybarList := util.ProtobufDecodePointList(params["ybar"].([]byte))
		prevKeyList := util.ProtobufDecodePointList(params["prev_keys"].([]byte))
		prevValList := util.ProtobufDecodePointList(params["prev_vals"].([]byte))
		prePublicKey := anonServer.Suite.Point()
		prePublicKey.UnmarshalBinary(params["public_key"].([]byte))

		// verify the shuffle
		verifier := shuffle.Verifier(anonServer.Suite, nil, prePublicKey, prevKeyList,
			prevValList, xbarList, ybarList)
		err := proof.HashVerify(anonServer.Suite, "PairShuffle", verifier, params["proof"].([]byte))
		if err != nil {
			panic("Shuffle verify failed: " + err.Error())
		}
	}
}

func handleRoundEnd(params map[string]interface{}) {
	keyList := util.ProtobufDecodePointList(params["keys"].([]byte))
	size := len(keyList)
	valList := util.ProtobufDecodePointList(params["vals"].([]byte))
	if _, ok := params["is_start"]; ok {
		// The request is sent by coordinator
	} else {
		// verify neff shuffle if needed
		verifyNeffShuffle(params)
	}

	// Create a public/private keypair (X[mine],x)
	X := make([]abstract.Point, 1)
	X[0] = anonServer.PublicKey

	// randomly select Ei
	E := anonServer.Suite.Secret().Pick(random.Stream)

	// update GT & HT
	GT := util.DecodePoint(anonServer.Suite, params["GT"].([]byte))
	HT := util.DecodePoint(anonServer.Suite, params["HT"].([]byte))
	GT.Mul(GT, E)
	HT.Mul(HT, E)


	newKeys := make([]abstract.Point, size)
	newVals := make([]abstract.Point, size)
	for i := 0 ; i < size; i++ {
		// decrypt the public key
		newKeys[i] = anonServer.KeyMap[keyList[i].String()]
		// randomize PComm
		newVals[i] = anonServer.Suite.Point().Mul(valList[i], E)
	}
	byteNewKeys := util.ProtobufEncodePointList(newKeys)
	byteNewVals := util.ProtobufEncodePointList(newVals)

	if(size <= 1) {
		// no need to shuffle, just send the package to next server
		pm := map[string]interface{}{
			"keys" : byteNewKeys,
			"vals" : byteNewVals,
			"GT": util.EncodePoint(GT),
			"HT": util.EncodePoint(HT),
		}
		event := &proto.Event{EventType:proto.ROUND_END, Params:pm}
		util.SendEvent(anonServer.LocalAddr, anonServer.PreviousHop, event)
		// reset RoundKey and key map
		anonServer.Roundkey = anonServer.Suite.Secret().Pick(random.Stream)
		anonServer.KeyMap = make(map[string]abstract.Point)
		return
	}

	Xori := make([]abstract.Point, len(newVals))
	for i:=0; i < size; i++ {
		Xori[i] = anonServer.Suite.Point().Mul(nil, anonServer.PrivateKey)
	}
	byteOri := util.ProtobufEncodePointList(Xori)

	rand := anonServer.Suite.Cipher(abstract.RandomKey)
	// *** perform neff shuffle here ***
	Xbar, Ybar, _, Ytmp, prover := neffShuffle(Xori, newKeys, rand)
	prf, err := proof.HashProve(anonServer.Suite, "PairShuffle", rand, prover)
	util.CheckErr(err)


	// this is the shuffled key
	finalKeys := convertToOrigin(Ybar, Ytmp)
	finalVals := rebindReputation(newKeys, newVals, finalKeys)

	// send data to the next server
	byteXbar := util.ProtobufEncodePointList(Xbar)
	byteYbar := util.ProtobufEncodePointList(Ybar)
	byteFinalKeys := util.ProtobufEncodePointList(finalKeys)
	byteFinalVals := util.ProtobufEncodePointList(finalVals)
	bytePublicKey, _ := anonServer.PublicKey.MarshalBinary()
	// prev keys means the key before shuffle
	pm := map[string]interface{}{
		"xbar" : byteXbar,
		"ybar" : byteYbar,
		"keys" : byteFinalKeys,
		"vals" : byteFinalVals,
		"proof" : prf,
		"prev_keys": byteOri,
		"prev_vals": byteNewKeys,
		"shuffled": true,
		"public_key" : bytePublicKey,
		"GT": util.EncodePoint(GT),
		"HT": util.EncodePoint(HT),
	}
	event := &proto.Event{EventType:proto.ROUND_END, Params:pm}
	util.SendEvent(anonServer.LocalAddr, anonServer.PreviousHop, event)

	// reset RoundKey and key map
	anonServer.Roundkey = anonServer.Suite.Secret().Pick(random.Stream)
	anonServer.KeyMap = make(map[string]abstract.Point)
}

func handleBroadcastPedersenH(params map[string]interface{}) {
	anonServer.PedersenBase.HT = util.DecodePoint(anonServer.Suite, params["h"].([]byte))
}

func rebindReputation(newKeys []abstract.Point, newVals []abstract.Point, finalKeys []abstract.Point) (finalVals []abstract.Point) {
	size := len(newKeys)
	finalVals = make([]abstract.Point, size)
	mapVals := make(map[string]abstract.Point)
	for i := 0; i < size; i++ {
		mapVals[newKeys[i].String()] = newVals[i]
	}
	for i := 0; i < size; i++ {
		finalVals[i] = mapVals[finalKeys[i].String()]
	}
	return finalVals
}

func convertToOrigin(YbarEn, Ytmp []abstract.Point) ([]abstract.Point){
	size := len(YbarEn)
	yyy := make([]abstract.Point, size)

	for i := 0; i < size; i++ {
		yyy[i] = YbarEn[i]
		Ytmp[i].Sub(yyy[i], Ytmp[i])
	}
	return Ytmp
}

// Y is the keys want to shuffle
func neffShuffle(X []abstract.Point, Y []abstract.Point, rand abstract.Cipher) (Xbar, Ybar, Xtmp, Ytmp []abstract.Point, prover proof.Prover){

	Xbar, Ybar, prover, Xtmp, Ytmp = shuffle.Shuffle(anonServer.Suite, nil, anonServer.PublicKey,
		X, Y, rand)
	return
}

// encrypt the public key and PComm, then send to next hop
func handleClientRegisterServerSide(params map[string]interface{}) {
	publicKey := anonServer.Suite.Point()
	err := publicKey.UnmarshalBinary(params["public_key"].([]byte))
	util.CheckErr(err)

	newKey := anonServer.Suite.Point().Mul(publicKey, anonServer.Roundkey)
	byteNewKey, err := newKey.MarshalBinary()
	util.CheckErr(err)
	pm := map[string]interface{}{
		"public_key" : byteNewKey,
		"addr" : params["addr"].(string),
		"pcomm": params["pcomm"].([]byte),
	}
	event := &proto.Event{EventType:proto.CLIENT_REGISTER_SERVERSIDE, Params:pm}
	util.SendEvent(anonServer.LocalAddr, anonServer.NextHop, event)
	// add into key map
	fmt.Println("[debug] Receive client register request... ")
	anonServer.KeyMap[newKey.String()] = publicKey
}

func handleUpdateNextHop(params map[string]interface{}) {
	addr, err := net.ResolveTCPAddr("tcp",params["next_hop"].(string))
	util.CheckErr(err)
	anonServer.NextHop = addr
}

func handleAnnouncement(params map[string]interface{}) {
	var g abstract.Point = nil
	keyList := util.ProtobufDecodePointList(params["keys"].([]byte))
	valList := util.ProtobufDecodePointList(params["vals"].([]byte))
	size := len(keyList)
	GT := util.DecodePoint(anonServer.Suite, params["GT"].([]byte))
	HT := util.DecodePoint(anonServer.Suite, params["HT"].([]byte))

	// randomly pick Ei
	E := anonServer.Suite.Secret().Pick(random.Stream)
	// update GT & HT
	GT.Mul(GT, E)
	HT.Mul(HT, E)

	if val, ok := params["g"]; ok {
		// contains g
		byteG := val.([]byte)
		g = anonServer.Suite.Point()
		g.UnmarshalBinary(byteG)
		g = anonServer.Suite.Point().Mul(g, anonServer.Roundkey)
		// verify the previous shuffle
		verifyNeffShuffle(params)
	}else {
		g = anonServer.Suite.Point().Mul(nil, anonServer.Roundkey)
	}

	// update table
	newKeys := make([]abstract.Point, size)
	newVals := make([]abstract.Point, size)
	for i := 0 ; i < len(keyList); i++ {
		// encrypt the public key using modPow
		newKeys[i] = anonServer.Suite.Point().Mul(keyList[i], anonServer.Roundkey)
		// randomize PComm
		PComm := anonServer.Suite.Point().Mul(valList[i], E)
		newVals[i] = PComm
		// update key map
		anonServer.KeyMap[newKeys[i].String()] = keyList[i]
	}
	byteNewKeys := util.ProtobufEncodePointList(newKeys)
	byteNewVals := util.ProtobufEncodePointList(newVals)
	byteG := util.EncodePoint(g)

	if(size <= 1) {
		// no need to shuffle, just send the package to next server
		pm := map[string]interface{}{
			"keys" : byteNewKeys,
			"vals" : byteNewVals,
			"g" : byteG,
			"GT": util.EncodePoint(GT),
			"HT": util.EncodePoint(HT),
		}
		event := &proto.Event{EventType:proto.ANNOUNCEMENT, Params:pm}
		util.SendEvent(anonServer.LocalAddr, anonServer.NextHop, event)
		return
	}

	Xori := make([]abstract.Point, len(newVals))
	for i:=0; i < size; i++ {
		Xori[i] = anonServer.Suite.Point().Mul(nil, anonServer.PrivateKey)
	}
	byteOri := util.ProtobufEncodePointList(Xori)

	rand := anonServer.Suite.Cipher(abstract.RandomKey)
	// *** perform neff shuffle here ***
	Xbar, Ybar, _, Ytmp, prover := neffShuffle(Xori,newKeys,rand)
	prf, err := proof.HashProve(anonServer.Suite, "PairShuffle", rand, prover)
	util.CheckErr(err)


	// this is the shuffled key
	finalKeys := convertToOrigin(Ybar, Ytmp)
	finalVals := rebindReputation(newKeys, newVals, finalKeys)

	// send data to the next server
	byteXbar := util.ProtobufEncodePointList(Xbar)
	byteYbar := util.ProtobufEncodePointList(Ybar)
	byteFinalKeys := util.ProtobufEncodePointList(finalKeys)
	byteFinalVals := util.ProtobufEncodePointList(finalVals)
	bytePublicKey, _ := anonServer.PublicKey.MarshalBinary()
	// prev keys means the key before shuffle
	pm := map[string]interface{}{
		"xbar" : byteXbar,
		"ybar" : byteYbar,
		"keys" : byteFinalKeys,
		"vals" : byteFinalVals,
		"proof" : prf,
		"prev_keys": byteOri,
		"prev_vals": byteNewKeys,
		"shuffled": true,
		"public_key" : bytePublicKey,
		"g" : byteG,
		"GT": util.EncodePoint(GT),
		"HT": util.EncodePoint(HT),
	}
	event := &proto.Event{EventType:proto.ANNOUNCEMENT, Params:pm}
	util.SendEvent(anonServer.LocalAddr, anonServer.NextHop, event)
}

// handle announcement finalize, which receives parameters from coordinator
func handleAnnouncementFinalize(params map[string]interface{}) {
	g := util.DecodePoint(anonServer.Suite, params["g"].([]byte))
	
	// update GT & HT
	GT := util.DecodePoint(anonServer.Suite, params["GT"].([]byte))
	HT := util.DecodePoint(anonServer.Suite, params["HT"].([]byte))
	anonServer.PedersenBase.GT = GT
	anonServer.PedersenBase.HT = HT

	//construct Decrypted reputation map
	keyList := util.ProtobufDecodePointList(params["keys"].([]byte))
	valList := util.ProtobufDecodePointList(params["vals"].([]byte))
	anonServer.EndingCommMap = make(map[string]abstract.Point)
	anonServer.EndingKeyMap = make(map[string]abstract.Point)
	// anonServer.ReputationDiffMap = make(map[string]int)
	// anonServer.AllClientsPublicKeys = keyList

	for i := 0; i < len(keyList); i++ {
		anonServer.AddIntoEndingMap(keyList[i], valList[i])
	}

	// set new g
	anonServer.G = g
}

func handleSignAssignments(params map[string]interface{}, senderAddr *net.TCPAddr) {
	// extract info from params
	nymR := anonServer.Suite.Point()
	byteNymR := params["nym"].([]byte)
	err := nymR.UnmarshalBinary(byteNymR)
	util.CheckErr(err)
	PCommr := anonServer.EndingCommMap[nymR.String()]

	// verify the proof
	if !bridge.VerifyInd(params, PCommr, anonServer.Suite, anonServer.PedersenBase, anonServer.FujiOkamBase) {
		fmt.Print("[note]** Fails to verify the proof...")
		pm := map[string]interface{}{
			"success": false,
		}
		event := &proto.Event{EventType:proto.GOT_SIGNS, Params:pm}
		util.SendEvent(anonServer.LocalAddr, senderAddr, event)
		return
	}

	// sign assignments
	assignments := bridge.DecodeAssignmentList(params["assignments"].([]byte))
	sigs := [][]byte{}
	for _,assignment := range assignments {
		byteAssignment := bridge.EncodeAssignment(&assignment)
		rand := anonServer.Suite.Cipher([]byte("example"))
		sig := util.ElGamalSign(anonServer.Suite, rand, byteAssignment, anonServer.PrivateKey, anonServer.Suite.Point())
		sigs = append(sigs, sig)
	}

	// send signatures back to coordinator
	byteSigs := util.Encode2DByteArray(sigs)
	pm := map[string]interface{}{
		"success": true,
		"assignments": params["assignments"],
		"signatures": byteSigs,
	}
	event := &proto.Event{EventType:proto.GOT_SIGNS, Params:pm}
	util.SendEvent(anonServer.LocalAddr, senderAddr, event)
}

// handle server register reply
func handleServerRegisterReply(params map[string]interface{}, addr *net.TCPAddr) {
	reply := params["reply"].(bool)
	// store the address of previous hop
	if val, ok := params["prev_server"]; ok {
		ServerAddr, _ := net.ResolveTCPAddr("tcp",val.(string))
		// we assume resolving TCP address never fails
		anonServer.PreviousHop = ServerAddr
	}
	if reply {
		anonServer.IsConnected = true
	}

	// setup fujiokam
	N := new(big.Int).SetBytes(params["n"].([]byte))
	fujiokamBase := fujiokam.CreateMinimumBase(anonServer.Suite, N)
	fujiokamBase.G1 = fujiokamBase.Point().FromBinary(params["g1"].([]byte))
	fujiokamBase.G2 = fujiokamBase.Point().FromBinary(params["g2"].([]byte))
	fujiokamBase.G3 = fujiokamBase.Point().FromBinary(params["g3"].([]byte))
	fujiokamBase.G4 = fujiokamBase.Point().FromBinary(params["g4"].([]byte))
	fujiokamBase.G5 = fujiokamBase.Point().FromBinary(params["g5"].([]byte))
	fujiokamBase.G6 = fujiokamBase.Point().FromBinary(params["g6"].([]byte))
	fujiokamBase.H1 = fujiokamBase.Point().FromBinary(params["h1"].([]byte))
	anonServer.FujiOkamBase = fujiokamBase

	// update h
	h := anonServer.Suite.Point()
	err := h.UnmarshalBinary(params["h"].([]byte))
	util.CheckErr(err)
	r := anonServer.Suite.Secret().Pick(random.Stream)
	h.Mul(h, r)
	// encode h
	byteH, err := h.MarshalBinary()
	util.CheckErr(err)
	pm := map[string]interface{}{
		"h": byteH,
	}
	// tell coordinator updated h
	event := &proto.Event{EventType:proto.UPDATE_PEDERSEN_H, Params:pm}
	util.SendEvent(anonServer.LocalAddr, addr, event)
}