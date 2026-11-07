package models

type TokenType string

const (
	BEARER_TOKEN_TYPE TokenType = "Bearer"
)

type UniversalAuthCredential struct {
	ClientID     string
	ClientSecret string
}

type AccessTokenCredential struct {
	AccessToken string
}

type GCPIDTokenCredential struct {
	IdentityID string
}

type GCPIAMCredential struct {
	IdentityID                string
	ServiceAccountKeyFilePath string
}

type AWSIAMCredential struct {
	IdentityID string
}

type KubernetesCredential struct {
	IdentityID          string
	ServiceAccountToken string
}

type AzureCredential struct {
	IdentityID string
	Resource   string
	ClientID   string
}

type OIDCCredential struct {
	IdentityID string
	JWT        string
}

type JWTCredential struct {
	IdentityID string
	JWT        string
}

type LDAPCredential struct {
	IdentityID string
	Username   string
	Password   string
}

type OCICredential struct {
	IdentityID  string
	PrivateKey  string
	Fingerprint string
	UserID      string
	TenancyID   string
	Region      string
	Passphrase  *string
}
