package server

import (
	"fmt"
	"net"
	"time"

	// "log"
	"bytes"
	"io"
	"strconv"
	"zRep/primitive/pedersen"
	"zRep/proto"
	"zRep/util"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/nist"
	"github.com/dedis/crypto/random"
)

// var anonServer *server.AnonServer
var config map[string]string

/**
  * register itself to controller
  */
func serverRegister() {
	// set the parameters to register
	bytePublicKey, _ := anonServer.PublicKey.MarshalBinary()
	params := map[string]interface{}{
		"public_key": bytePublicKey,
	}
	event := &proto.Event{EventType:proto.SERVER_REGISTER, Params:params}

	util.SendEvent(anonServer.LocalAddr, anonServer.CoordinatorAddr, event)
}

/**
 * start anon server listener to handle event
 */
func startAnonServerListener(listener *net.TCPListener) {
	fmt.Println("[debug] AnonServer Listener started...");
	buf := new(bytes.Buffer)
	for {
		buf.Reset()
		conn, err := listener.AcceptTCP()
		util.CheckErr(err)
		_, err = io.Copy(buf, conn)
		util.CheckErr(err)
		Handle(buf.Bytes(), anonServer)
	}
}

/**
 * initialize anon server
 * set ip, port and encryption parameters
 */
func initAnonServer() {
	config = util.ReadConfig()
	// load controller ip and port
	CoordinatorAddr, err := net.ResolveTCPAddr("tcp",config["coordinator_ip"]+":"+ config["coordinator_port"])
	util.CheckErr(err)
	// initialize suite
	suite := nist.NewAES128SHA256QR512()
	a := suite.Secret().Pick(random.Stream)
	A := suite.Point().Mul(nil, a)
	RoundKey := suite.Secret().Pick(random.Stream)
	pedersenBase := pedersen.CreateMinimalBaseFromSuite(suite)

	anonServer = &AnonServer{
		CoordinatorAddr: CoordinatorAddr,
		Suite: suite,
		PrivateKey: a,
		PublicKey: A,
		OnetimePseudoNym: suite.Point(),
		G: nil,
		EndingCommMap: make(map[string]abstract.Point),
		EndingKeyMap: make(map[string]abstract.Point),
		IsConnected: false,
		NextHop: CoordinatorAddr,
		PreviousHop: CoordinatorAddr,
		KeyMap: make(map[string]abstract.Point),
		A: nil,
		Roundkey: RoundKey,
		PedersenBase: pedersenBase,
		FujiOkamBase: nil,
	}
}

func Launch() {
	// init anon server
	initAnonServer()
	fmt.Println("[debug] AnonServer started...");
	// check available port
	localPort, err := strconv.Atoi(config["local_port"])
	util.CheckErr(err)
	var listener *net.TCPListener
	for i := localPort; i <= localPort+10; i++ {
		addr := &net.TCPAddr{IP: net.IPv4zero, Port: i}
		listener, err = net.ListenTCP("tcp", addr)
		if err == nil {
			anonServer.LocalAddr = addr
			break
		}
	}

	// start Listener
	go startAnonServerListener(listener)
	// register itself to coordinator
	serverRegister()

	// wait until register successful
	for {
		if anonServer.IsConnected {
			break
		}
		time.Sleep(1000 * time.Millisecond)
	}

	fmt.Println("[debug] Register success...")
	for {
		time.Sleep(100000000 * time.Millisecond)
	}

	// fmt.Println("[debug] Exit system...");

}
