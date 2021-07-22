package client

import (
	"math/big"
	"net"
	"zRep/cmd/bridge"
	"zRep/primitive/fujiokam"
	"zRep/primitive/pedersen"

	"github.com/dedis/crypto/abstract"
)

// data structure to store all the necessary data in client

type AssignmentInfo struct {
	Assignment *bridge.Assignment
	ByteSignatures []byte
}

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
	ControllerPublicKey abstract.Point
	OnetimePseudoNym abstract.Point
	G abstract.Point
	Reputation int
	AllClientsPublicKeys []abstract.Point
	Index int
	Assignments []AssignmentInfo

	PCommr abstract.Point
	R abstract.Secret
	FujiOkamBase *fujiokam.FujiOkamBase
	PedersenBase *pedersen.PedersenBase
	AllGnHonestyProofPublic []*big.Int
	AllGnHonestyChallenge []bool
}

func (dissentClient *DissentClient) ClearBuffer() {
	dissentClient.Assignments = nil
}

func (dissentClient *DissentClient) AddAssignment(assignment *bridge.Assignment, byteSignatures []byte) {
	info := AssignmentInfo{Assignment: assignment, ByteSignatures: byteSignatures}
	dissentClient.Assignments = append(dissentClient.Assignments, info)
}