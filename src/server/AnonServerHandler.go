package server
import (
	"net"
	"../proto"
	"encoding/gob"
	"bytes"
	"../util"
	"fmt"
	"github.com/dedis/crypto/abstract"
	"../github.com/dedis/crypto/shuffle"
	"github.com/dedis/crypto/proof"
	"github.com/dedis/crypto/random"
	// "github.com/dedis/crypto/anon"
)

var srcAddr *net.UDPAddr
var anonServer *AnonServer

func Handle(buf []byte, addr *net.UDPAddr, tmpServer *AnonServer, n int) {
	// decode the whole message
	byteArr := make([]util.ByteArray,2)
	gob.Register(byteArr)

	srcAddr = addr
	anonServer = tmpServer
	event := &proto.Event{}
	err := gob.NewDecoder(bytes.NewReader(buf[:n])).Decode(event)
	util.CheckErr(err)
	switch event.EventType {
	case proto.SERVER_REGISTER_REPLY:
		handleServerRegisterReply(event.Params, addr);
		break
	case proto.ANNOUNCEMENT:
		handleAnnouncement(event.Params);
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
		util.Send(anonServer.Socket, anonServer.PreviousHop, util.Encode(event))
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
	Xbar, Ybar, _, Ytmp, prover := neffShuffle(Xori,newKeys, rand)
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
	util.Send(anonServer.Socket, anonServer.PreviousHop, util.Encode(event)) 

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
	util.Send(anonServer.Socket, anonServer.NextHop, util.Encode(event))
	// add into key map
	fmt.Println("[debug] Receive client register request... ")
	anonServer.KeyMap[newKey.String()] = publicKey
}

func handleUpdateNextHop(params map[string]interface{}) {
	addr, err := net.ResolveUDPAddr("udp",params["next_hop"].(string))
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

	// randomly pick Ei
	E := anonServer.Suite.Secret().Pick(random.Stream)
	// update GT & HT
	GT.Mul(GT, E)
	HT.Mul(HT, E)

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
		util.Send(anonServer.Socket, anonServer.NextHop, util.Encode(event))
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
	util.Send(anonServer.Socket, anonServer.NextHop, util.Encode(event))
}

// handle server register reply
func handleServerRegisterReply(params map[string]interface{}, addr *net.UDPAddr) {
	reply := params["reply"].(bool)
	if val, ok := params["prev_server"]; ok {
		ServerAddr, _  := net.ResolveUDPAddr("udp",val.(string))
		anonServer.PreviousHop = ServerAddr
	}
	if reply {
		anonServer.IsConnected = true
	}

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
	util.Send(anonServer.Socket, addr, util.Encode(event))
}