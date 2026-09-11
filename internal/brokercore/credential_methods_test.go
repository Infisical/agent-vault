package brokercore

import (
	"context"
	"errors"
	"testing"

	"github.com/Infisical/agent-vault/internal/broker"
)

func TestInject_MethodAllowed(t *testing.T) {
	key32 := make32(0x51)
	f := newFakeCredStore()
	f.setServices(t, "v1", []broker.Service{{
		Host:    "api.example.com",
		Methods: []string{"GET", "HEAD"},
		Auth:    broker.Auth{Type: "bearer", Token: "MY_TOKEN"},
	}})
	f.setCred(t, key32, "v1", "MY_TOKEN", "s3cret")

	p := NewStoreCredentialProvider(f, key32)
	res, err := p.Inject(context.Background(), "v1", "api.example.com", 0, "/", "GET")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.Headers["Authorization"] != "Bearer s3cret" {
		t.Fatalf("got Authorization=%q", res.Headers["Authorization"])
	}
	if !res.MethodRestricted {
		t.Fatal("MethodRestricted should be true for a service with a Methods list")
	}
}

func TestInject_MethodDenied(t *testing.T) {
	key32 := make32(0x52)
	f := newFakeCredStore()
	f.setServices(t, "v1", []broker.Service{{
		Host:    "api.example.com",
		Methods: []string{"GET", "HEAD"},
		Auth:    broker.Auth{Type: "bearer", Token: "MY_TOKEN"},
	}})
	f.setCred(t, key32, "v1", "MY_TOKEN", "s3cret")

	p := NewStoreCredentialProvider(f, key32)
	_, err := p.Inject(context.Background(), "v1", "api.example.com", 0, "/", "DELETE")
	if !errors.Is(err, ErrMethodNotAllowed) {
		t.Fatalf("want ErrMethodNotAllowed, got %v", err)
	}
	var mna *MethodNotAllowedError
	if !errors.As(err, &mna) {
		t.Fatalf("want *MethodNotAllowedError, got %T", err)
	}
	if mna.Method != "DELETE" || len(mna.Allowed) != 2 || mna.Allowed[0] != "GET" {
		t.Fatalf("unexpected error detail: %+v", mna)
	}
	// The check must run before credential resolution: a denied request
	// must not decrypt or touch the credential in any form.
	if f.getCredentialCalls != 0 {
		t.Fatalf("credential store consulted %d times for a denied method", f.getCredentialCalls)
	}
}

func TestInject_MethodDeniedBlocksSubstitutionsOnPassthrough(t *testing.T) {
	key32 := make32(0x53)
	f := newFakeCredStore()
	f.setServices(t, "v1", []broker.Service{{
		Host:    "api.example.com",
		Methods: []string{"GET"},
		Auth:    broker.Auth{Type: "passthrough"},
		Substitutions: []broker.Substitution{{
			Key: "SIGNING_KEY", Placeholder: "__signing_key__",
		}},
	}})
	f.setCred(t, key32, "v1", "SIGNING_KEY", "sig-secret")

	p := NewStoreCredentialProvider(f, key32)
	_, err := p.Inject(context.Background(), "v1", "api.example.com", 0, "/", "POST")
	if !errors.Is(err, ErrMethodNotAllowed) {
		t.Fatalf("want ErrMethodNotAllowed, got %v", err)
	}
	if f.getCredentialCalls != 0 {
		t.Fatalf("substitution credential resolved %d times for a denied method", f.getCredentialCalls)
	}
}

func TestInject_NoMethodsAllowsAll(t *testing.T) {
	key32 := make32(0x54)
	f := newFakeCredStore()
	f.setServices(t, "v1", []broker.Service{{
		Host: "api.example.com",
		Auth: broker.Auth{Type: "bearer", Token: "MY_TOKEN"},
	}})
	f.setCred(t, key32, "v1", "MY_TOKEN", "s3cret")

	p := NewStoreCredentialProvider(f, key32)
	res, err := p.Inject(context.Background(), "v1", "api.example.com", 0, "/", "DELETE")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.MethodRestricted {
		t.Fatal("MethodRestricted should be false when the service has no Methods list")
	}
}
