package coordinator

import (
	"math/big"
	"net"
	"zRep/primitive/fujiokam"
	"zRep/primitive/lrs"
	"zRep/primitive/pedersen"
	"zRep/cmd/bridge"

	"github.com/dedis/crypto/abstract"
)

type ClientTuple struct {
	Nym abstract.Point
	PComm abstract.Point
}

type BridgeInfo struct {
	Nym abstract.Point
	Used bool
}

type Coordinator struct {
	// local address
	LocalAddr *net.TCPAddr
	// network topology for server cluster
	ServerList []*net.TCPAddr
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
	// h for Pedersen

	// store client address
	Clients map[string]*net.TCPAddr
	// store reputation map
	BeginningKeyMap map[string]abstract.Point
	BeginningCommMap map[string]abstract.Point
	// we only add new clients at the beginning of each round
	// store the new clients's one-time pseudo nym
	NewClientsBuffer []ClientTuple
	// msg sender's record nym
	MsgLog []abstract.Point
	// record each vote signature's y0
	VoteRecords []*big.Int

	Bridges map[string]BridgeInfo

	EndingKeyMap map[string]abstract.Point
	EndingCommMap map[string]abstract.Point
	ReputationDiffMap map[string]int

	AllClientsPublicKeys []abstract.Point

	PedersenBase *pedersen.PedersenBase
	FujiOkamBase *fujiokam.FujiOkamBase
	LRSBase *lrs.LRSBase

	AllGnHonestyProofSecret []*big.Int
	AllGnHonestyProofPublic []*big.Int
}

// get last server in topology
func (c *Coordinator) GetLastServer() *net.TCPAddr {
	if len(c.ServerList) == 0 {
		return nil
	}
	return c.ServerList[len(c.ServerList)-1]
}

// get first server in topology
func (c *Coordinator) GetFirstServer() *net.TCPAddr {
	if len(c.ServerList) == 0 {
		return nil
	}
	return c.ServerList[0]
}

func (c *Coordinator) AddClient(key abstract.Point, val *net.TCPAddr) {
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
func (c *Coordinator) AddServer(addr *net.TCPAddr){
	c.ServerList = append(c.ServerList,addr)
}

// add msg log and return msg id
func (c *Coordinator) AddMsgLog(log abstract.Point) int{
	c.MsgLog = append(c.MsgLog,log)
	return len(c.MsgLog)
}

func (c *Coordinator) AddBridge(bridgeAddr string, nym abstract.Point) {
	c.Bridges[bridgeAddr] = BridgeInfo{Nym:nym, Used:false}
}

func (c *Coordinator) GetBridge() *bridge.Bridge {
	for bridgeAddr,info := range c.Bridges {
		if !info.Used {
			return &bridge.Bridge{Addr:bridgeAddr, Nym:info.Nym}
		}
	}
	return nil
}

func (c *Coordinator) GetBridges(num int) []bridge.Bridge {
	res := []bridge.Bridge{}
	for num > 0 {
		br := c.GetBridge()
		if br == nil {
			return res
		}
		res = append(res, *br)
		num = num - 1
	}
	return res
}

func (c *Coordinator) AssignBridges(num int, nymR abstract.Point) []bridge.Assignment {
	brs := c.GetBridges(num)
	res := []bridge.Assignment{}
	for _,br := range brs {
		assignment := bridge.Assignment{NymR:nymR, Bridge:br}
		res = append(res, assignment)
	}
	return res
}

func (c *Coordinator) ClearBridges() {
	c.Bridges = make(map[string]BridgeInfo)
}

// get reputation
func (c *Coordinator) GetReputationDiff(key abstract.Point) int{
	return c.ReputationDiffMap[key.String()]
}

func (c *Coordinator) AddClientInBuffer(nym abstract.Point, PComm abstract.Point) {
	c.NewClientsBuffer = append(c.NewClientsBuffer, ClientTuple{Nym:nym, PComm:PComm})
}

func (c *Coordinator) AddIntoEndingMap(key abstract.Point, val abstract.Point) {
	keyStr := key.String()
	c.EndingKeyMap[keyStr] = key
	c.EndingCommMap[keyStr] = val
}

func (c *Coordinator) AddIntoRepMap(key abstract.Point, val abstract.Point) {
	keyStr := key.String()
	c.BeginningKeyMap[keyStr] = key
	c.BeginningCommMap[keyStr] = val
}

func (c *Coordinator) ClearVoteRecords() {
	c.VoteRecords = []*big.Int{}
}

func (c *Coordinator) IsLinkableRecord(y0 *big.Int) bool {
	for _, r := range c.VoteRecords {
		if r.Cmp(y0) == 0 {
			return true
		}
	}
	return false
}

func (c *Coordinator) AddToVoteRecords(y0 *big.Int) {
	c.VoteRecords = append(c.VoteRecords, y0)
}