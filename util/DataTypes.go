package util

import (
	"github.com/dedis/crypto/abstract"
	"math/big"
)

type SecretList struct {
	Secrets []abstract.Secret
}

type PointList struct {
	Points []abstract.Point
}

type BoolList struct {
	Bools []bool
}

type BigIntList struct {
	BigInts []*big.Int
}

type BytesArray struct {
	Bytes [][]byte
}

type Pair struct {
	key, val interface{}
}

type ByteArray struct {
	Arr []byte
}
