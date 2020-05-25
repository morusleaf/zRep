package main

import (
	"fmt"
	"net"
	"./proto"
	 "./util"
	"./client"
	"strconv"
	"github.com/dedis/crypto/nist"
	"github.com/dedis/crypto/random"
	"bufio"
	"os"
	"strings"
	"log"
	"time"
	"math/big"
	"./primitive/pedersen"
	"./primitive/pedersen_fujiokam"
	"./primitive/lrs"
)

// pointer to client itself
var dissentClient  *client.DissentClient

/**
  * register itself to controller
  */
func register() {
	// set the parameters to register
	bytePublicKey, _ := dissentClient.PublicKey.MarshalBinary()
	params := map[string]interface{}{
		"public_key": bytePublicKey,
	}
	event := &proto.Event{EventType:proto.CLIENT_REGISTER_CONTROLLERSIDE, Params:params}

	util.SendToCoodinator(dissentClient.Socket, util.Encode(event))
}

/**
  * start listener to handle event
  */
func startClientListener() {
	fmt.Println("[debug] Client Listener started...");
	buf := make([]byte, 100000)
	for {
		n,addr,err := dissentClient.Socket.ReadFromUDP(buf)
		if err != nil {
			log.Fatal(err)
		}
		client.Handle(buf, addr, dissentClient, n) // a goroutine handles conn so that the loop can accept other connections
	}
}

/**
  * send message text to server
  */
func sendMsg(ind int, text string) {
	if ind > dissentClient.Reputation {
		fmt.Println("indicator should be less or equal than reputation")
		return
	}
	d := dissentClient.Reputation - ind
	bigD := new(big.Int).SetInt64(int64(d))
	xD := dissentClient.Suite.Secret().SetInt64(int64(d))

	// compute PComm for d
	PCommr := dissentClient.PCommr
	xind := dissentClient.Suite.Secret().SetInt64(int64(ind))
	PCommind, rind := dissentClient.PedersenBase.Commit(xind)
	PCommd := dissentClient.PedersenBase.Sub(PCommr, PCommind)
	bytePCommind, err := PCommind.MarshalBinary()
	util.CheckErr(err)
	bytePCommd, err := PCommd.MarshalBinary()
	util.CheckErr(err)
	byteRind, err := rind.MarshalBinary()
	util.CheckErr(err)

	// generate ARGnonneg
	FOCommd, rFOCommd := dissentClient.FujiOkamBase.Commit(bigD)
	ARGnonneg := dissentClient.FujiOkamBase.ProveNonneg(bigD, FOCommd, rFOCommd)

	// generate ARGequal
	rd := dissentClient.Suite.Secret().Sub(dissentClient.R, rind)
	ARGequal := pedersen_fujiokam.ProveEqual(dissentClient.PedersenBase, dissentClient.FujiOkamBase, xD, PCommd, rd, FOCommd, rFOCommd)

	// generate signature
	rand := dissentClient.Suite.Cipher([]byte("example"))
	sig := util.ElGamalSign(dissentClient.Suite, rand, []byte(text), dissentClient.PrivateKey, dissentClient.G)
	// serialize Point data structure
	byteNym, _ := dissentClient.OnetimePseudoNym.MarshalBinary()

	// wrap params
	params := map[string]interface{}{
		"text": text,
		"nym": byteNym,
		"signature": sig,
		"FOCommd": FOCommd.ToBinary(),
		"PCommd": bytePCommd,
		"PCommind": bytePCommind,
		"rind": byteRind,
		"arg_nonneg": util.EncodeARGnonneg(ARGnonneg),
		"arg_equal": util.EncodeARGequal(ARGequal),
	}
	event := &proto.Event{EventType:proto.MESSAGE, Params:params}
	// send to coordinator
	util.SendToCoodinator(dissentClient.Socket, util.Encode(event))
}

/**
  * send vote to server
  */
func sendVote(msgID, vote int) {
	// vote can be only 1 or -1
	if vote > 0 {
		vote = 1;
	}else {
		vote = -1;
	}
	v := strconv.Itoa(vote)
	m := strconv.Itoa(msgID)
	text :=  m + ";" + v

	// generate signature for msgID
	base := lrs.CreateBase(util.PointToBigInt(dissentClient.G))
	sig := base.Sign(util.IntToByte(msgID), len(dissentClient.AllClientsPublicKeys), dissentClient.Index, dissentClient.PrivateKey, dissentClient.AllClientsPublicKeys)
	byteSig := lrs.ProtobufEncodeSignature(sig)
	// serialize Point data structure
	byteNym, _ := dissentClient.OnetimePseudoNym.MarshalBinary()
	// wrap params
	params := map[string]interface{}{
		"text": text,
		"nym":byteNym,
		"signature":byteSig,
	}
	event := &proto.Event{EventType:proto.VOTE, Params:params}
	// send to coordinator
	util.SendToCoodinator(dissentClient.Socket, util.Encode(event))
}


/**
  * initialize anonClient and encrypted parameters
  */
func initClient() {
	// load controller ip and port
	config := util.ReadConfig()
	ServerAddr,err := net.ResolveUDPAddr("udp", config["coordinator_ip"]+":"+ config["coordinator_port"])
	util.CheckErr(err)
	// initialize suite
	suite := nist.NewAES128SHA256QR512()
	a := suite.Secret().Pick(random.Stream)
	A := suite.Point().Mul(nil, a)
	dissentClient = &client.DissentClient{
		CoordinatorAddr: ServerAddr,
		Socket: nil,
		Status: client.CONFIGURATION,
		Suite: suite,
		PrivateKey: a,
		PublicKey: A,
		OnetimePseudoNym: suite.Point(),
		G: nil,
		Reputation: 0,
		FujiOkamBase: nil,
		PedersenBase: pedersen.CreateBaseFromSuite(suite),
	}
}


func launchClient() {
	// initialize parameters and server configurations
	initClient()
	fmt.Println("[debug] Client started...");
	// make udp connection to controller
	conn, err := net.DialUDP("udp", nil, dissentClient.CoordinatorAddr)
	util.CheckErr(err)
	// set socket
	dissentClient.Socket = conn
	// start Listener
	go startClientListener()
	fmt.Println("[debug] My public key is: ")
	fmt.Println(dissentClient.PublicKey)
	// register itself to controller
	register()

	// wait until register successful
	for ; dissentClient.Status != client.MESSAGE ; {
		time.Sleep(500 * time.Millisecond)
	}

	// read command and process
	reader := bufio.NewReader(os.Stdin)
	Loop:
	for {
		data, _, _ := reader.ReadLine()
		command := string(data)
		commands := strings.Split(command, " ")
		switch commands[0] {
		case "msg":
			ind,_ := strconv.Atoi(commands[1])
			sendMsg(ind, commands[2])
			break;
		case "vote":
			msgID,_ := strconv.Atoi(commands[1])
			vote, _ := strconv.Atoi(commands[2])
			sendVote(msgID, vote)
			break;
		case "exit":
			break Loop
		}
	}
	// close connection
	conn.Close()
	fmt.Println("[debug] Exit system...");
}