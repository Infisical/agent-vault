package cmd

import "testing"

func TestAdvertisedMITMAddrExplicit(t *testing.T) {
	t.Setenv("AGENT_VAULT_MITM_ADDR", "http://agent-vault:14322")
	got, explicit, err := advertisedMITMAddr("http://127.0.0.1:14321", 9)
	if err != nil {
		t.Fatal(err)
	}
	if !explicit || got != "http://agent-vault:14322" {
		t.Fatalf("got %q explicit=%v", got, explicit)
	}
}

func TestAdvertisedMITMAddrDerived(t *testing.T) {
	t.Setenv("AGENT_VAULT_MITM_ADDR", "")
	got, explicit, err := advertisedMITMAddr("http://vault.internal:14321", 14322)
	if err != nil {
		t.Fatal(err)
	}
	if explicit || got != "http://vault.internal:14322" {
		t.Fatalf("got %q explicit=%v", got, explicit)
	}
}

func TestAdvertisedMITMAddrRejectsNonBaseHTTP(t *testing.T) {
	cases := []string{
		"https://agent-vault:14322",
		"http://user:pass@agent-vault:14322",
		"http://agent-vault:14322/callback",
		"http://agent-vault:14322/",
		"http://agent-vault:14322?x=1",
		"http://agent-vault:14322#frag",
		"http://agent-vault:notaport",
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			t.Setenv("AGENT_VAULT_MITM_ADDR", raw)
			if _, _, err := advertisedMITMAddr("http://127.0.0.1:14321", 14322); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}
