package coordinator

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"zRep/primitive/fujiokam"
	"zRep/primitive/pedersen"
	"zRep/proto"
	"zRep/util"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/nist"
	"github.com/dedis/crypto/random"
)

// pointer to coordinator itself
// var anonCoordinator *Coordinator

/**
 * start server listener to handle event
 */
func startServerListener(listener *net.TCPListener) {
	fmt.Println("[debug] Coordinator server listener started...");
	buf := new(bytes.Buffer)
	for {
		buf.Reset()
		conn, err := listener.AcceptTCP()
		util.CheckErr(err)
		_, err = io.Copy(buf, conn)
		util.CheckErr(err)
		Handle(buf.Bytes(), anonCoordinator)
	}
}

/**
  * initialize coordinator
  */
func initCoordinator() {
	config := util.ReadConfig()
	CoordinatorAddr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:"+config["local_port"])
	util.CheckErr(err)
	suite := nist.NewAES128SHA256QR512()
	a := suite.Secret().Pick(random.Stream)
	A := suite.Point().Mul(nil, a)
	pedersenBase := pedersen.CreateMinimalBaseFromSuite(suite)
	fujiokamBase := fujiokam.CreateBaseFromSuite(suite)
	prfSecret, prfPublic := fujiokamBase.GenerateAllGnHonestyProof()

	anonCoordinator = &Coordinator{
		LocalAddr: CoordinatorAddr,
		ServerList: nil,
		Status: CONFIGURATION,
		Suite: suite,
		PrivateKey: a,
		PublicKey: A,
		G: nil,
		Clients: make(map[string]*net.TCPAddr),
		BeginningKeyMap: make(map[string]abstract.Point),
		BeginningCommMap: make(map[string]abstract.Point),
		NewClientsBuffer: nil,
		MsgLog: nil,
		Bridges: make(map[string]BridgeInfo),
		EndingCommMap: make(map[string]abstract.Point),
		EndingKeyMap: make(map[string]abstract.Point),
		ReputationDiffMap: make(map[string]int),
		PedersenBase: pedersenBase,
		FujiOkamBase: fujiokamBase,
		AllGnHonestyProofSecret: prfSecret,
		AllGnHonestyProofPublic: prfPublic,
	}
}

// config parameters for commitments
func configCommParams() {
	// Config Pedersen Commitment
	h := anonCoordinator.PedersenBase.HT
	byteH, err := h.MarshalBinary()
	util.CheckErr(err)
	// broadcast hT
	params := map[string]interface{}{
		"h": byteH,
	}
	event := &proto.Event{EventType: proto.BCAST_PEDERSEN_H, Params: params}
	for _, server := range anonCoordinator.ServerList {
		util.SendEvent(anonCoordinator.LocalAddr, server, event)
	}
}

/**
 * clear all buffer data
 */
func clearBuffer() {
	// clear buffer
	anonCoordinator.NewClientsBuffer = nil
	// msg sender's record nym
	anonCoordinator.MsgLog = nil
}

/**
  * send announcement signal to first server
  * send reputation list
  */
func announce() {
	firstServer := anonCoordinator.GetFirstServer()
	if firstServer == nil {
		anonCoordinator.Status = MESSAGE
		return
	}
	// construct reputation list (public keys & reputation commitments)
	size := len(anonCoordinator.BeginningCommMap)
	keys := make([]abstract.Point, size)
	vals := make([]abstract.Point, size)
	i := 0
	for k, v := range anonCoordinator.BeginningCommMap {
		keys[i] = anonCoordinator.BeginningKeyMap[k]
		vals[i] = v
		i++
	}
	byteKeys := util.ProtobufEncodePointList(keys)
	byteVals := util.ProtobufEncodePointList(vals)
	params := map[string]interface{}{
		"keys" : byteKeys,
		"vals" : byteVals,
		"GT": util.EncodePoint(anonCoordinator.PedersenBase.GT),
		"HT": util.EncodePoint(anonCoordinator.PedersenBase.HT),
	}
	event := &proto.Event{EventType:proto.ANNOUNCEMENT, Params:params}
	util.SendEvent(anonCoordinator.LocalAddr, firstServer, event)
}

/**
 * send round-end signal to last server in topology
 * add new clients into the reputation map
 */
func roundEnd() {
	lastServer := anonCoordinator.GetLastServer()
	if lastServer == nil {
		anonCoordinator.Status = READY_FOR_NEW_ROUND
		return
	}
	// add new clients into reputation map
	for _,cdata := range anonCoordinator.NewClientsBuffer {
		anonCoordinator.AddIntoEndingMap(cdata.Nym, cdata.PComm)
	}
	// add previous clients into reputation map
	// construct the parameters
	size := len(anonCoordinator.EndingCommMap)
	keys := make([]abstract.Point, size)
	vals := make([]abstract.Point, size)
	rDiffs := make([]abstract.Secret, size)
	i := 0
	for k, v := range anonCoordinator.EndingCommMap {
		keys[i] = anonCoordinator.EndingKeyMap[k]
		// update commitment by adding diff's commitment
		diff := anonCoordinator.ReputationDiffMap[k]
		diffSecret := anonCoordinator.Suite.Secret().SetInt64(int64(diff))
		diffComm, rDiff := anonCoordinator.PedersenBase.Commit(diffSecret)
		vals[i] = anonCoordinator.PedersenBase.Add(v, diffComm)
		rDiffs[i] = rDiff
		i++
	}
	byteKeys := util.ProtobufEncodePointList(keys)
	byteVals := util.ProtobufEncodePointList(vals)
	// send signal to server
	pm := map[string]interface{} {
		"keys" : byteKeys,
		"vals" : byteVals,
		"is_start" : true,
		"GT": util.EncodePoint(anonCoordinator.PedersenBase.GT),
		"HT": util.EncodePoint(anonCoordinator.PedersenBase.HT),
	}
	event := &proto.Event{EventType:proto.ROUND_END, Params:pm}
	util.SendEvent(anonCoordinator.LocalAddr, lastServer, event)

	// send rDiff to clients
	pm = map[string]interface{} {
		"keys" : byteKeys,
		"rDiffs": util.ProtobufEncodeSecretList(rDiffs),
	}
	event = &proto.Event{EventType:proto.BCAST_PEDERSEN_RDIFF, Params:pm}
	for _, addr := range anonCoordinator.Clients {
		util.SendEvent(anonCoordinator.LocalAddr, addr, event)
	}

	// clear bridges
	anonCoordinator.ClearBridges()
}

/**
 * start vote phase, actually, if we partition the clients to servers,
 * we can let server send this signal to clients. Here, for simplicity, we
 * just send it from controller
 */
func vote() {
	anonCoordinator.ClearVoteRecords()
	pm := map[string]interface{} {}
	event := &proto.Event{EventType:proto.VOTE, Params:pm}
	for _, addr :=  range anonCoordinator.Clients {
		util.SendEvent(anonCoordinator.LocalAddr, addr, event)
	}
}

func waitKeypress(prompt string) {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	reader.ReadLine()
}

func Launch() {
	// init coordinator
	initCoordinator()
	// bind to socket
	listener, err := net.ListenTCP("tcp", anonCoordinator.LocalAddr)
	util.CheckErr(err)
	// start listener
	go startServerListener(listener)
	fmt.Println("** Note: Type ok to finish the server configuration. **")
	// read ok to start life cycle
	waitKeypress("Press ENTER to start:\n")
	fmt.Println("[debug] Servers in the current network:")
	fmt.Println(anonCoordinator.ServerList)
	fmt.Println("Configuring parameters of commitments.")
	configCommParams()
	anonCoordinator.Status = READY_FOR_NEW_ROUND
	for {
		// wait for the status changed to READY_FOR_NEW_ROUND
		for {
			if anonCoordinator.Status == READY_FOR_NEW_ROUND {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		// clear buffer at the beginning of each round
		clearBuffer()
		fmt.Println("******************** New round begin ********************")
		if anonCoordinator.Status != READY_FOR_NEW_ROUND {
			log.Fatal("Fails to be ready for the new round")
			os.Exit(1)
		}
		// waitKeypress("Press ENTER to start new round: ")
		anonCoordinator.Status = ANNOUNCE
		fmt.Println("[coordinator] Announcement phase started...")
		// start announce phase
		announce()
		for {
			if anonCoordinator.Status == MESSAGE {
				break
			}
			time.Sleep(1000 * time.Millisecond)
		}
		// start message and vote phase
		fmt.Println("[coordinator] Messaging phase started...")
		// 10 secs for msg
		// time.Sleep(10000 * time.Millisecond)
		waitKeypress("Press ENTER to end posting:\n")
		vote()
		fmt.Println("[coordinator] Voting phase started...")
		// 10 secs for vote
		// time.Sleep(10000 * time.Millisecond)
		waitKeypress("Press ENTER to finish voting:\n")
		roundEnd()
	}
}
