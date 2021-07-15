package client
import (
	"github.com/dedis/crypto/abstract"
	"net"
	"zRep/primitive/fujiokam"
	"zRep/primitive/pedersen"
	"math/big"
)


// data structure to store all the necessary data in client

type DissentClient struct {
	// client-side config
	CoordinatorAddr *net.TCPAddr
	LocalAddr *net.TCPAddr
	Socket *net.TCPConn
	Status int
	// crypto variables
	Suite abstract.Suite
	PrivateKey abstract.Secret
	PublicKey abstract.Point
	OnetimePseudoNym abstract.Point
	G abstract.Point
	Reputation int
	AllClientsPublicKeys []abstract.Point
	Index int

	PCommr abstract.Point
	R abstract.Secret
	FujiOkamBase *fujiokam.FujiOkamBase
	PedersenBase *pedersen.PedersenBase
	AllGnHonestyProofPublic []*big.Int
	AllGnHonestyChallenge []bool
}