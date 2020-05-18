package main
import (
	// "./primitive"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/random"
	"github.com/dedis/crypto/nist"
	"fmt"
	"reflect"
	"math/big"
)

func checkr(x abstract.Secret) bool {
	V := x.(*nist.Int).V
	M := x.(*nist.Int).M
	// V % 2 != 0
	if V.Bit(0) == 0 {
		return false
	}
	q,_ := new(big.Int).SetString("5099133861178675934299038070513690140208594154615901954959232152506056770707302268711370548280642524887896017588520836152823386566007063045571431221913131", 10)
	
	q.Rem(q, M)
	// V != q (mod M)
	if V.Cmp(q) == 0 {
		return false
	}
	return true
}

func test() {
	suite := nist.NewAES128SHA256QR512()
	var a abstract.Secret = nil
	for {
		a = suite.Secret().Pick(random.Stream)
		if checkr(a) {
			break
		}
	}
	fmt.Println(a)
	fmt.Println(reflect.TypeOf(suite.Point()))
	fmt.Println(reflect.TypeOf(suite.Secret()))
}