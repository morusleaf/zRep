package util
import (
	"log"
	"bytes"
	"crypto/cipher"
	"errors"
	"github.com/dedis/crypto/abstract"
	"encoding/binary"
	// "os"
	"net"
	"encoding/gob"
	"reflect"
	"github.com/dedis/protobuf"
	"github.com/dedis/crypto/nist"

	"github.com/dedis/crypto/random"
	"../primitive/fujiokam"
	"../primitive/pedersen_fujiokam"
	"math/big"
)

func SerializeTwoDimensionArray(arr [][]byte) []ByteArray{
	byteArr := make([]ByteArray,len(arr))
	gob.Register(byteArr)
	for i := 0; i < len(arr); i++ {
		byteArr[i].Arr = arr[i]
	}
	return byteArr
}

func Encode(event interface{}) []byte {
	var network bytes.Buffer
	err := gob.NewEncoder(&network).Encode(event)
	CheckErr(err)
	return network.Bytes()
}

func Send(conn *net.UDPConn, addr *net.UDPAddr,content []byte) {
	_,err := conn.WriteToUDP(content, addr)
	if err != nil {
		panic(err.Error())
	}
}

func SendToCoodinator(conn *net.UDPConn, content []byte) {
	_,err := conn.Write(content)
	if err != nil {
		panic(err.Error())
	}
}

func CheckErr(err error) {
	if err != nil {
		panic(err.Error())
		// os.Exit(1)
	}
}

// ****************************************************************************
// Gn honesty proof
// ****************************************************************************

func EncodeBigInt(arg *big.Int) []byte {
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	err := encoder.Encode(arg)
	if err != nil {
		panic(err.Error())
	}
	return buf.Bytes()
}

func DecodeBigInt(data []byte) *big.Int {
	arg := new(big.Int)
	buf := bytes.NewReader(data)
	decoder := gob.NewDecoder(buf)
	err := decoder.Decode(arg)
	if err != nil {
		panic(err)
	}
	return arg
}

func ProtobufEncodeBoolList(list []bool) []byte {
	byteNym, err := protobuf.Encode(&BoolList{list})
	if err != nil {
		panic(err.Error())
	}
	return byteNym
}

func ProtobufDecodeBoolList(bytes []byte) []bool {
	var aPoint bool
	var tPoint = reflect.TypeOf(&aPoint).Elem()
	cons := protobuf.Constructors {
		tPoint: func()interface{} { return true },
	}

	var msg BoolList
	if err := protobuf.DecodeWithConstructors(bytes, &msg, cons); err != nil {
		panic(err)
	}
	return msg.Bools
}

func ProtobufEncodeBigIntList(ints []*big.Int) []byte {
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	err := encoder.Encode(ints)
	if err != nil {
		panic(err.Error())
	}
	return buf.Bytes()
}

func ProtobufDecodeBigIntList(data []byte) []*big.Int {
	var arg []*big.Int
	buf := bytes.NewReader(data)
	decoder := gob.NewDecoder(buf)
	err := decoder.Decode(&arg)
	if err != nil {
		log.Fatal(err)
	}
	return arg
}

// ****************************************************************************
// Non-negative argument for Fujisaki-Okamoto commitment
// ****************************************************************************

func EncodeARGnonneg(arg *fujiokam.ARGnonneg) []byte {
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	err := encoder.Encode(arg)
	if err != nil {
		panic(err.Error())
	}
	return buf.Bytes()
}

func DecodeARGnonneg(data []byte) *fujiokam.ARGnonneg {
	arg := new(fujiokam.ARGnonneg)
	buf := bytes.NewReader(data)
	decoder := gob.NewDecoder(buf)
	err := decoder.Decode(arg)
	if err != nil {
		log.Fatal(err)
	}
	return arg
}

// ****************************************************************************
// Equality argument for Pedersen and Fujisaki-Okamoto commitments
// ****************************************************************************

func EncodeARGequal(arg *pedersen_fujiokam.ARGequal) []byte {
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	err := encoder.Encode(arg)
	if err != nil {
		panic(err.Error())
	}
	return buf.Bytes()
}

func DecodeARGequal(data []byte) *pedersen_fujiokam.ARGequal {
	arg := new(pedersen_fujiokam.ARGequal)
	buf := bytes.NewReader(data)
	decoder := gob.NewDecoder(buf)
	err := decoder.Decode(arg)
	if err != nil {
		log.Fatal(err)
	}
	return arg
}

// ****************************************************************************
// Encode list
// ****************************************************************************

func EncodeIntArray(arr []int) []byte {
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	err := encoder.Encode(arr)
	if err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func DecodeIntArray(data []byte) []int {
	var arr []int
	buf := bytes.NewReader(data)
	decoder := gob.NewDecoder(buf)
	err := decoder.Decode(&arr)
	if err != nil {
		log.Fatal(err)
	}
	return arr
}

func ProtobufEncodePointList(plist []abstract.Point) []byte {
	byteNym, err := protobuf.Encode(&PointList{plist})
	if err != nil {
		panic(err.Error())
	}
	return byteNym
}

func ProtobufDecodePointList(bytes []byte) []abstract.Point {
	var aPoint abstract.Point
	var tPoint = reflect.TypeOf(&aPoint).Elem()
	suite := nist.NewAES128SHA256QR512()
	cons := protobuf.Constructors {
		tPoint: func()interface{} { return suite.Point() },
	}

	var msg PointList
	if err := protobuf.DecodeWithConstructors(bytes, &msg, cons); err != nil {
		log.Fatal(err)
	}
	return msg.Points
}

func ProtobufEncodeSecretList(plist []abstract.Secret) []byte {
	byteNym, err := protobuf.Encode(&SecretList{plist})
	if err != nil {
		panic(err.Error())
	}
	return byteNym
}

func ProtobufDecodeSecretList(bytes []byte) []abstract.Secret {
	var aSecret abstract.Secret
	var tSecret = reflect.TypeOf(&aSecret).Elem()
	suite := nist.NewAES128SHA256QR512()
	cons := protobuf.Constructors {
		tSecret: func()interface{} { return suite.Secret() },
	}

	var msg SecretList
	if err := protobuf.DecodeWithConstructors(bytes, &msg, cons); err != nil {
		log.Fatal(err)
	}
	return msg.Secrets
}

func ByteToInt(b []byte) int {
	myInt:= binary.BigEndian.Uint32(b)

	return int(myInt)
}

func IntToByte(n int) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf,uint32(n))
	return buf
}

func FindCommUsingKeyList(keyList, valList []abstract.Point, EList []abstract.Secret, nym abstract.Point) (abstract.Point, abstract.Secret) {
	for i, k := range keyList {
		if nym.Equal(k) {
			return valList[i], EList[i]
		}
	}
	return nil, nil
}

func FindIntUsingKeyList(keyList []abstract.Point, diffList []int, nym abstract.Point) int {
	for i, k := range keyList {
		if nym.Equal(k) {
			return diffList[i]
		}
	}
	// if client has not joined last round, then her key will not showup in keyList
	return 0
}

// crypto

// A basic, verifiable signature
type basicSig struct {
	C abstract.Secret // challenge
	R abstract.Secret // response
}

// Returns a secret that depends on on a message and a point
func hashElGamal(suite abstract.Suite, message []byte, p abstract.Point) abstract.Secret {
	pb, _ := p.MarshalBinary()
	c := suite.Cipher(pb)
	c.Message(nil, nil, message)
	return suite.Secret().Pick(c)
}

// This simplified implementation of ElGamal Signatures is based on
// crypto/anon/sig.go
// The ring structure is removed and
// The anonimity set is reduced to one public key = no anonimity
func ElGamalSign(suite abstract.Suite, random cipher.Stream, message []byte,
privateKey abstract.Secret, g abstract.Point) []byte {

	// Create random secret v and public point commitment T
	v := suite.Secret().Pick(random)
	T := suite.Point().Mul(g, v)

	// Create challenge c based on message and T
	c := hashElGamal(suite, message, T)

	// Compute response r = v - x*c
	r := suite.Secret()
	r.Mul(privateKey, c).Sub(v, r)

	// Return verifiable signature {c, r}
	// Verifier will be able to compute v = r + x*c
	// And check that hashElgamal for T and the message == c
	buf := bytes.Buffer{}
	sig := basicSig{c, r}
	abstract.Write(&buf, &sig, suite)
	return buf.Bytes()
}

func ElGamalVerify(suite abstract.Suite, message []byte, publicKey abstract.Point,
signatureBuffer []byte, g abstract.Point) error {

	// Decode the signature
	buf := bytes.NewBuffer(signatureBuffer)
	sig := basicSig{}
	if err := abstract.Read(buf, &sig, suite); err != nil {
		return err
	}
	r := sig.R
	c := sig.C

	// Compute base**(r + x*c) == T
	var P, T abstract.Point
	P = suite.Point()
	T = suite.Point()
	T.Add(T.Mul(g, r), P.Mul(publicKey, c))

	// Verify that the hash based on the message and T
	// matches the challange c from the signature
	c = hashElGamal(suite, message, T)
	if !c.Equal(sig.C) {
		return errors.New("invalid signature")
	}

	return nil
}


func ElGamalEncrypt(suite abstract.Suite, pubkey abstract.Point, M abstract.Point) (
K, C abstract.Point, remainder []byte) {

	// Embed the message (or as much of it as will fit) into a curve point.
	//M, remainder := suite.Point().Pick(message, random.Stream)

	// ElGamal-encrypt the point to produce ciphertext (K,C).
	k := suite.Secret().Pick(random.Stream) // ephemeral private key
	K = suite.Point().Mul(nil, k)           // ephemeral DH public key
	S := suite.Point().Mul(pubkey, k)       // ephemeral DH shared secret
	C = S.Add(S, M)                         // message blinded with secret
	return
}

func ElGamalDecrypt(suite abstract.Suite, prikey abstract.Secret, K, C abstract.Point) (
M abstract.Point) {

	// ElGamal-decrypt the ciphertext (K,C) to reproduce the message.
	S := suite.Point().Mul(K, prikey) // regenerate shared secret
	M = suite.Point().Sub(C, S)      // use to un-blind the message
	return
}


// get the final data by message, _ = M.data()