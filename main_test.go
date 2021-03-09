package main

import (
	"testing"
)

func TestAddrAllowedNoDomain(t *testing.T) {
	allowedAddrs := []string{"joe@abc.com"}
	if addrAllowed("bob.com", allowedAddrs) {
		t.FailNow()
	}
}

func TestAddrAllowedSingle(t *testing.T) {
	allowedAddrs := []string{"joe@abc.com"}

	if !addrAllowed("joe@abc.com", allowedAddrs) {
		t.FailNow()
	}
	if addrAllowed("bob@abc.com", allowedAddrs) {
		t.FailNow()
	}
}

func TestAddrAllowedDifferentCase(t *testing.T) {
	allowedAddrs := []string{"joe@abc.com"}
	testAddrs := []string{
		"joe@ABC.com",
		"Joe@abc.com",
		"JOE@abc.com",
		"JOE@ABC.COM",
	}
	for _, addr := range testAddrs {
		if !addrAllowed(addr, allowedAddrs) {
			t.Errorf("Address %v not allowed, but should be", addr)
		}
	}
}

func TestAddrAllowedLocal(t *testing.T) {
	allowedAddrs := []string{"joe"}

	if !addrAllowed("joe", allowedAddrs) {
		t.FailNow()
	}
	if addrAllowed("bob", allowedAddrs) {
		t.FailNow()
	}
}

func TestAddrAllowedMulti(t *testing.T) {
	allowedAddrs := []string{"joe@abc.com", "bob@def.com"}
	if !addrAllowed("joe@abc.com", allowedAddrs) {
		t.FailNow()
	}
	if !addrAllowed("bob@def.com", allowedAddrs) {
		t.FailNow()
	}
	if addrAllowed("bob@abc.com", allowedAddrs) {
		t.FailNow()
	}
}

func TestAddrAllowedSingleDomain(t *testing.T) {
	allowedAddrs := []string{"@abc.com"}
	if !addrAllowed("joe@abc.com", allowedAddrs) {
		t.FailNow()
	}
	if addrAllowed("joe@def.com", allowedAddrs) {
		t.FailNow()
	}
}

func TestAddrAllowedMixed(t *testing.T) {
	allowedAddrs := []string{"app", "app@example.com", "@appsrv.example.com"}
	if !addrAllowed("app", allowedAddrs) {
		t.FailNow()
	}
	if !addrAllowed("app@example.com", allowedAddrs) {
		t.FailNow()
	}
	if addrAllowed("ceo@example.com", allowedAddrs) {
		t.FailNow()
	}
	if !addrAllowed("root@appsrv.example.com", allowedAddrs) {
		t.FailNow()
	}
	if !addrAllowed("dev@appsrv.example.com", allowedAddrs) {
		t.FailNow()
	}
	if addrAllowed("appsrv@example.com", allowedAddrs) {
		t.FailNow()
	}
}
