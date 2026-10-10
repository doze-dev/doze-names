package names

import (
	"errors"
	"testing"
)

func TestAStackNameBelongsToOneProject(t *testing.T) {
	home := t.TempDir()
	first := Open(home, "doze")
	release, err := first.ClaimStack("shop", "/work/shop")
	if err != nil {
		t.Fatal(err)
	}

	other := Open(home, "doze")
	other.pid = livePID(t) // a different, living daemon
	_, err = other.ClaimStack("shop", "/elsewhere/shop")
	var taken *ErrStackTaken
	if !errors.As(err, &taken) || taken.Dir != "/work/shop" {
		t.Fatalf("a second project claiming the name = %v, want ErrStackTaken naming /work/shop", err)
	}
	// The same project, restarted under a new pid, takes its own name over.
	if _, err := other.ClaimStack("shop", "/work/shop"); err != nil {
		t.Fatalf("the same project claiming again: %v", err)
	}
	// A different name is nobody's business.
	if _, err := other.ClaimStack("blog", "/elsewhere/blog"); err != nil {
		t.Fatal(err)
	}

	// The claim is bookkeeping: it is not a name, and it does not resolve.
	if _, leaked := first.Snapshot()["shop.doze"]; leaked {
		t.Fatal("a stack claim must not create a name")
	}
	if ip := first.Resolve("db.shop.doze"); ip != nil {
		t.Fatalf("a stack claim made db.shop.doze resolve to %v", ip)
	}

	// Released, the name is free for anyone.
	_ = release // first no longer holds it: other took it over above
	third := Open(home, "doze")
	third.pid = livePID(t)
	if _, err := third.ClaimStack("blog", "/third/blog"); err == nil {
		t.Fatal("blog is held by a live process and should be refused")
	}
}

func TestStackNamesThatWouldCollideWithTheApex(t *testing.T) {
	for name, want := range map[string]bool{"aws": true, "kafka": true, "AWS": true, "shop": false, "awsome": false} {
		if got := ReservedStack(name); got != want {
			t.Errorf("ReservedStack(%q) = %v, want %v", name, got, want)
		}
	}
}
