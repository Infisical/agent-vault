package test

// import (
// 	"context"
// 	"encoding/json"
// 	"fmt"
// 	"os"
// 	"testing"

// 	infisical "github.com/infisical/go-sdk"
// )

// func TestSshIssueCreds(t *testing.T) {
// 	client := infisical.NewInfisicalClient(context.Background(), infisical.Config{
// 		SiteUrl:          "http://localhost:8080",
// 		AutoTokenRefresh: true,
// 	})

// 	// Authenticate using Universal Auth
// 	_, err := client.Auth().UniversalAuthLogin("", "")
// 	if err != nil {
// 		fmt.Printf("Authentication failed: %v\n", err)
// 		os.Exit(1)
// 	}

// 	// Test adding SSH host
// 	_, err = client.Ssh().AddSshHost(infisical.AddSshHostOptions{
// 		ProjectID: "",
// 		Hostname:  "",
// 		Alias:     "",
// 	})
// 	if err != nil {
// 		fmt.Printf("Failed to add SSH host: %v\n", err)
// 		os.Exit(1)
// 	}

// 	// Test getting SSH hosts the user has access to
// 	hosts, err := client.Ssh().GetSshHosts(infisical.GetSshHostsOptions{})
// 	if err != nil {
// 		t.Fatalf("Failed to fetch SSH hosts: %v", err)
// 	}

// 	if len(hosts) == 0 {
// 		t.Fatalf("No SSH hosts returned")
// 	}

// 	fmt.Println("Got SSH hosts:")
// 	for _, host := range hosts {
// 		fmt.Printf("- Host: %s (ID: %s)\n", host.Hostname, host.ID)
// 	}

// 	// Test getting user CA public key for first host
// 	userCaKey, err := client.Ssh().GetSshHostUserCaPublicKey(hosts[0].ID)
// 	if err != nil {
// 		t.Fatalf("Failed to get user CA public key: %v", err)
// 	}

// 	hostCaKey, err := client.Ssh().GetSshHostHostCaPublicKey(hosts[0].ID)
// 	if err != nil {
// 		t.Fatalf("Failed to get host CA public key: %v", err)
// 	}

// 	fmt.Printf("User CA Public Key for host %s:\n%s\n", hosts[0].Hostname, userCaKey)

// 	for _, host := range hosts {
// 		hostJson, err := json.MarshalIndent(host, "", "  ")
// 		if err != nil {
// 			t.Errorf("Failed to marshal host %s: %v", host.ID, err)
// 			continue
// 		}
// 		fmt.Println(string(hostJson))
// 	}

// 	// Pick the first host
// 	targetHost := hosts[0]

// 	// Test issuing SSH cert for user
// 	creds, err := client.Ssh().IssueSshHostUserCert(targetHost.ID, infisical.IssueSshHostUserCertOptions{
// 		LoginUser: "ec2-user", // or whatever login user is appropriate
// 	})
// 	if err != nil {
// 		t.Fatalf("Failed to issue SSH credentials from host %s: %v", targetHost.ID, err)
// 	}

// 	// Display the credentials
// 	credsJson, err := json.MarshalIndent(creds, "", "  ")
// 	if err != nil {
// 		t.Fatalf("Failed to marshal issued credentials: %v", err)
// 	}
// 	fmt.Println("Issued user credentials:")
// 	fmt.Println(string(credsJson))

// 	// Test issuing SSH cert for host
// 	creds2, err := client.Ssh().IssueSshHostHostCert(targetHost.ID, infisical.IssueSshHostHostCertOptions{
// 		PublicKey: "",
// 	})
// 	if err != nil {
// 		t.Fatalf("Failed to issue SSH credentials from host %s: %v", targetHost.ID, err)
// 	}

// 	// Display the credentials
// 	creds2Json, err := json.MarshalIndent(creds2, "", "  ")
// 	if err != nil {
// 		t.Fatalf("Failed to marshal issued credentials: %v", err)
// 	}
// 	fmt.Println("Issued credentials:")
// 	fmt.Println(string(creds2Json))

// 	// Test issuing SSH credentials
// 	creds, err := client.Ssh().IssueCredentials(infisical.IssueSshCredsOptions{
// 		CertificateTemplateID: "",
// 		Principals:            []string{"ec2-user"},
// 	})

// 	if err != nil {
// 		t.Fatalf("Failed to issue SSH credentials: %v", err)
// 	}

// 	// Test signing SSH public key
// 	creds2, err := client.Ssh().SignKey(infisical.SignSshPublicKeyOptions{
// 		CertificateTemplateID: "",
// 		Principals:            []string{"ec2-user"},
// 		PublicKey:             "ssh-rsa ...",
// 	})

// 	if err != nil {
// 		t.Fatalf("Failed to sign SSH public key: %v", err)
// 	}

// 	fmt.Print("Newly-issued SSH credentials: ", creds)
// 	fmt.Print("Signed SSH credential: ", creds2)
// }
