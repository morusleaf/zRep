package server
import (
	"net"
	"github.com/dedis/crypto/abstract"
	"../primitive/pedersen"
)


type AnonServer struct {
	// local address
	LocalAddr *net.TCPAddr
	// client-side config
	CoordinatorAddr *net.TCPAddr
	// crypto variables
	Suite abstract.Suite
	PrivateKey abstract.Secret
	PublicKey abstract.Point
	OnetimePseudoNym abstract.Point
	G abstract.Point


	// buffer data
	IsConnected bool
	// next hop in topology
	NextHop *net.TCPAddr
	// previous hop in topology
	PreviousHop *net.TCPAddr
	// map current public key with previous key
	KeyMap map[string]abstract.Point
	// generated by elgmal encryption
	A abstract.Point

	// used for modPow encryption
	Roundkey abstract.Secret

	PedersenBase *pedersen.PedersenBase

}