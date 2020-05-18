package coordinator
import (
	"github.com/dedis/crypto/abstract"
	"net"
	"../primitive/pedersen"
	"../primitive/fujiokam"
)

type ClientTuple struct {
	Nym abstract.Point
	PComm abstract.Point
}

type Coordinator struct {
	// local address
	LocalAddr *net.UDPAddr
	// socket
	Socket *net.UDPConn
	// network topology for server cluster
	ServerList []*net.UDPAddr
	// initialize the controller status
	Status int


	// crypto things
	Suite abstract.Suite
	// private key
	PrivateKey abstract.Secret
	// public key
	PublicKey abstract.Point
	// generator g
	G abstract.Point

	// store client address
	Clients map[string]*net.UDPAddr
	// store reputation map
	BeginningKeyMap map[string]abstract.Point
	BeginningMap map[string]abstract.Point
	// we only add new clients at the beginning of each round
	// store the new clients's one-time pseudo nym
	NewClientsBuffer []ClientTuple
	// msg sender's record nym
	MsgLog []abstract.Point

	EndingMap map[string]abstract.Point
	ReputationDiffMap map[string]int
	EndingKeyMap map[string]abstract.Point

	PedersenBase *pedersen.PedersenBase
	FujiOkamBase *fujiokam.FujiOkamBase

}

// get last server in topology
func (c *Coordinator) GetLastServer() *net.UDPAddr {
	if len(c.ServerList) == 0 {
		return nil
	}
	return c.ServerList[len(c.ServerList)-1]
}

// get first server in topology
func (c *Coordinator) GetFirstServer() *net.UDPAddr {
	if len(c.ServerList) == 0 {
		return nil
	}
	return c.ServerList[0]
}

func (c *Coordinator) AddClient(key abstract.Point, val *net.UDPAddr) {
	// delete the client who has same ip address
	for k,v := range c.Clients {
		if v.String() == val.String() {
			delete(c.Clients,k)
			break
		}
	}
	c.Clients[key.String()] = val
}

// add server into topology
func (c *Coordinator) AddServer(addr *net.UDPAddr){
	c.ServerList = append(c.ServerList,addr)
}

// add msg log and return msg id
func (c *Coordinator) AddMsgLog(log abstract.Point) int{
	c.MsgLog = append(c.MsgLog,log)
	return len(c.MsgLog)
}

// get reputation
func (c *Coordinator) GetReputationDiff(key abstract.Point) int{
	return c.ReputationDiffMap[key.String()]
}

func (c *Coordinator) AddClientInBuffer(nym abstract.Point, PComm abstract.Point) {
	c.NewClientsBuffer = append(c.NewClientsBuffer, ClientTuple{Nym:nym, PComm:PComm})
}

func (c *Coordinator) AddIntoDecryptedMap(key abstract.Point, val abstract.Point) {
	keyStr := key.String()
	c.EndingKeyMap[keyStr] = key
	c.EndingMap[keyStr] = val
}

func (c *Coordinator) AddIntoRepMap(key abstract.Point, val abstract.Point) {
	keyStr := key.String()
	c.BeginningKeyMap[keyStr] = key
	c.BeginningMap[keyStr] = val
}

