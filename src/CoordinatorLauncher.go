package main

import (

	"net"
	"fmt"
	"./util"
	"./coordinator"
	"bufio"
	"os"
	"github.com/dedis/crypto/nist"
	"github.com/dedis/crypto/random"
	"time"
	"log"
	"github.com/dedis/crypto/abstract"
	"./proto"
	"./primitive/pedersen"
	"./primitive/fujiokam"
)

// pointer to coordinator itself
var anonCoordinator *coordinator.Coordinator

/**
  * start server listener to handle event
  */
func startServerListener() {
	fmt.Println("[debug] Coordinator server listener started...");
	buf := make([]byte, 4096)
	for {
		n,addr,err := anonCoordinator.Socket.ReadFromUDP(buf)
		util.CheckErr(err)
		coordinator.Handle(buf,addr,anonCoordinator,n)
	}
}

/**
  * initialize coordinator
  */
func initCoordinator() {
	config := util.ReadConfig()
	fmt.Println(config)
	ServerAddr,err := net.ResolveUDPAddr("udp","127.0.0.1:"+config["local_port"])
	util.CheckErr(err)
	suite := nist.NewAES128SHA256QR512()
	a := suite.Secret().Pick(random.Stream)
	A := suite.Point().Mul(nil, a)
	pedersenBase := pedersen.CreateBaseFromSuite(suite)
	fujiokamBase := fujiokam.CreateBaseFromSuite(suite)

	anonCoordinator = &coordinator.Coordinator{
		LocalAddr: ServerAddr,
		Socket: nil,
		ServerList: nil,
		Status: coordinator.CONFIGURATION,
		Suite: suite,
		PrivateKey: a,
		PublicKey: A,
		G: nil,
		Clients: make(map[string]*net.UDPAddr),
		BeginningKeyMap: make(map[string]abstract.Point),
		BeginningMap: make(map[string]abstract.Point),
		NewClientsBuffer: nil,
		MsgLog: nil,
		EndingMap: make(map[string]abstract.Point),
		EndingKeyMap: make(map[string]abstract.Point),
		ReputationDiffMap: make(map[string]int),
		PedersenBase: pedersenBase,
		FujiOkamBase: fujiokamBase,
	}
}

// config parameters for commitments
func configCommParams() {
	// Config Pedersen Commitment
	base := anonCoordinator.PedersenBase
	h := base.H // TODO: generate this from all servers
	byteH, err := h.MarshalBinary()
	util.CheckErr(err)
	// broadcast hm
	params := map[string]interface{}{
		"h": byteH,
	}
	event := &proto.Event{EventType: proto.BCAST_PEDERSEN_H, Params: params}
	for _, server := range anonCoordinator.ServerList {
		util.Send(anonCoordinator.Socket, server, util.Encode(event))
	}

	// Config Fujisaki-Okamoto Commitment
	// TODO: publish parameters and non-neg proof
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
		anonCoordinator.Status = coordinator.MESSAGE
		return
	}
	// construct reputation list (public & encrypted reputation)
	size := len(anonCoordinator.BeginningMap)
	keys := make([]abstract.Point,size)
	vals := make([]abstract.Point,size)
	i := 0
	for k, v := range anonCoordinator.BeginningMap {
		keys[i] = anonCoordinator.BeginningKeyMap[k]
		vals[i] = v
		i++
	}
	byteKeys := util.ProtobufEncodePointList(keys)
	byteVals := util.ProtobufEncodePointList(vals)
	params := map[string]interface{}{
		"keys" : byteKeys,
		"vals" : byteVals,
	}
	event := &proto.Event{EventType:proto.ANNOUNCEMENT, Params:params}
	util.Send(anonCoordinator.Socket,firstServer,util.Encode(event))
}

/**
 * send round-end signal to last server in topology
 * add new clients into the reputation map
 */
func roundEnd() {
	lastServer := anonCoordinator.GetLastServer()
	if lastServer == nil {
		anonCoordinator.Status = coordinator.READY_FOR_NEW_ROUND
		return
	}
	// add new clients into reputation map
	for _,cdata := range anonCoordinator.NewClientsBuffer {
		anonCoordinator.AddIntoDecryptedMap(cdata.Nym, cdata.PComm)
	}
	// add previous clients into reputation map
	// construct the parameters
	size := len(anonCoordinator.EndingMap)
	keys := make([]abstract.Point,size)
	vals := make([]abstract.Point,size)
	i := 0
	for k, v := range anonCoordinator.EndingMap {
		keys[i] = anonCoordinator.EndingKeyMap[k]
		// update commitment by adding diff's commitment
		diff := anonCoordinator.ReputationDiffMap[k]
		diffSecret := anonCoordinator.Suite.Secret().SetInt64(int64(diff))
		diffComm, _ := anonCoordinator.PedersenBase.Commit(diffSecret)
		vals[i] = anonCoordinator.PedersenBase.Add(v, diffComm)
		i++
	}
	byteKeys := util.ProtobufEncodePointList(keys)
	byteVals := util.ProtobufEncodePointList(vals)
	// send signal to server
	pm := map[string]interface{} {
		"keys" : byteKeys,
		"vals" : byteVals,
		"is_start" : true,
	}
	event := &proto.Event{EventType:proto.ROUND_END, Params:pm}
	util.Send(anonCoordinator.Socket,lastServer,util.Encode(event))

}

/**
 * start vote phase, actually, if we partition the clients to servers,
 * we can let server send this signal to clients. Here, for simplicity, we
 * just send it from controller
 */
func vote() {
	pm := map[string]interface{} {}
	event := &proto.Event{EventType:proto.VOTE, Params:pm}
	for _, addr :=  range anonCoordinator.Clients {
		util.Send(anonCoordinator.Socket, addr, util.Encode(event))
	}
}

func waitKeypress(prompt string) {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	reader.ReadLine()
}

func launchCoordinator() {
	// init coordinator
	initCoordinator()
	// bind to socket
	conn, err := net.ListenUDP("udp",anonCoordinator.LocalAddr )
	util.CheckErr(err)
	anonCoordinator.Socket = conn
	// start listener
	go startServerListener()
	fmt.Println("** Note: Type ok to finish the server configuration. **")
	// read ok to start life cycle
	waitKeypress("Press enter to start:\n")
	fmt.Println("[debug] Servers in the current network:")
	fmt.Println(anonCoordinator.ServerList)
	fmt.Println("Configuring parameters of commitments.")
	configCommParams()
	anonCoordinator.Status = coordinator.READY_FOR_NEW_ROUND
	for {
		// wait for the status changed to READY_FOR_NEW_ROUND
		for i := 0; i < 100; i++ {
			if anonCoordinator.Status == coordinator.READY_FOR_NEW_ROUND {
				break
			}
			time.Sleep(1000 * time.Millisecond)
		}
		// clear buffer at the beginning of each round
		clearBuffer()
		fmt.Println("******************** New round begin ********************")
		if anonCoordinator.Status != coordinator.READY_FOR_NEW_ROUND {
			log.Fatal("Fails to be ready for the new round")
			os.Exit(1)
		}
		// waitKeypress("Press enter to start new round: ")
		anonCoordinator.Status = coordinator.ANNOUNCE
		fmt.Println("[coordinator] Announcement phase started...")
		// start announce phase
		announce()
		for i := 0; i < 100; i++ {
			if anonCoordinator.Status == coordinator.MESSAGE {
				break
			}
			time.Sleep(1000 * time.Millisecond)
		}
		if anonCoordinator.Status != coordinator.MESSAGE {
			log.Fatal("Fails to be ready for message phase")
			os.Exit(1)
		}
		// start message and vote phase
		fmt.Println("[coordinator] Messaging phase started...")
		// 10 secs for msg
		time.Sleep(10000 * time.Millisecond)
		// waitKeypress("Press enter to start voting: ")
		vote()
		fmt.Println("[coordinator] Voting phase started...")
		// 10 secs for vote
		time.Sleep(10000 * time.Millisecond)
		// waitKeypress("Press enter to finish voting: ")
		roundEnd()
	}
}