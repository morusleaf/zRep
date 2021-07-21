package bridge
import (
	"testing"
	"github.com/dedis/crypto/random"
	"fmt"

	"github.com/dedis/crypto/nist"
)

func TestEncodingAssignment(t *testing.T) {
	suite := nist.NewAES128SHA256QR512()
	p1 := suite.Point().Mul(nil, suite.Secret().Pick(random.Stream))
	p2 := suite.Point().Mul(nil, suite.Secret().Pick(random.Stream))
	assign := Assignment{Addr:"xxx", Nym:p1, NymR:p2}

	data := EncodeAssignment(&assign)
	assign2 := *DecodeAssignment(data)

	s1 := fmt.Sprint(assign)
	s2 := fmt.Sprint(assign2)
	if s1 != s2 {
		fmt.Println(s1)
		fmt.Println(s2)
		t.Error("Decoded assignment is different from the origin")
	}
}

func TestEncodingAssignmentList(t *testing.T) {
	suite := nist.NewAES128SHA256QR512()
	p1 := suite.Point().Mul(nil, suite.Secret().Pick(random.Stream))
	p2 := suite.Point().Mul(nil, suite.Secret().Pick(random.Stream))
	assign1 := Assignment{Addr:"xxx", Nym:p1, NymR:p2}
	assign2 := Assignment{Addr:"yyy", Nym:p2, NymR:p1}
	var alist []Assignment
	alist = append(alist, assign1)
	alist = append(alist, assign2)

	data := EncodeAssignmentList(alist)
	alist2 := DecodeAssignmentList(data)

	s1 := fmt.Sprint(alist)
	s2 := fmt.Sprint(alist2)

	if s1 != s2 {
		fmt.Println(s1)
		fmt.Println(s2)
		t.Error("Decoded assignment list is different from the origin")
	}
}