package pedersen
import (
	"testing"
)

func TestCreation(t *testing.T) {
	CreateBase()
}

func TestCommit(t *testing.T) {
	base := CreateBase()
	x := base.Suite.Secret().SetInt64(100)

	commit,r := base.Commit(x)
	if !base.Verify(x, r, commit) {
		t.Error("Verifification failed")
	}
}

func TestAdd(t *testing.T) {
	base := CreateBase()
	x0 := base.Suite.Secret().SetInt64(10)
	x1 := base.Suite.Secret().SetInt64(2)
	x := base.Suite.Secret().Add(x0, x1)

	commit0,r0 := base.Commit(x0)
	commit1,r1 := base.Commit(x1)
	commit := base.Add(commit0, commit1)
	r := base.Suite.Secret().Add(r0, r1)
	if !base.Verify(x, r, commit) {
		t.Error("Verifification failed")
	}
}

func TestSub(t *testing.T) {
	base := CreateBase()
	x0 := base.Suite.Secret().SetInt64(0)
	x1 := base.Suite.Secret().SetInt64(-2)
	x := base.Suite.Secret().Add(x0, x1)

	commit0,r0 := base.Commit(x0)
	commit1,r1 := base.Commit(x1)	
	commit := base.Add(commit0, commit1)
	r := base.Suite.Secret().Add(r0, r1)
	if !base.Verify(x, r, commit) {
		t.Error("Verifification failed")
	}
}