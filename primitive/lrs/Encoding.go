
package lrs

import (
	"bytes"
	"encoding/gob"
)

func ProtobufEncodeSignature(sig *Signature) []byte {
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	err := encoder.Encode(sig)
	if err != nil {
		panic(err.Error())
	}
	return buf.Bytes()
}

func ProtobufDecodeSignature(data []byte) *Signature {
	sig := &Signature{}
	buf := bytes.NewReader(data)
	decoder := gob.NewDecoder(buf)
	err := decoder.Decode(sig)
	if err != nil {
		panic(err)
	}
	return sig
}
