package api

// JWT auth:
type JwtAuthLoginRequest struct {
	IdentityID       string `json:"identityId"`
	JWT              string `json:"jwt"`
	OrganizationSlug string `json:"organizationSlug,omitempty"`
}

// Revoke access token:
type RevokeAccessTokenRequest struct {
	AccessToken string `json:"accessToken"`
}

type RevokeAccessTokenResponse struct {
	Message string `json:"message"`
}

// Universal auth:
type UniversalAuthLoginRequest struct {
	ClientID         string `json:"clientId"`
	ClientSecret     string `json:"clientSecret"`
	OrganizationSlug string `json:"organizationSlug,omitempty"`
}

// Kubernetes auth:
type KubernetesAuthLoginRequest struct {
	IdentityID       string `json:"identityId"`
	JWT              string `json:"jwt"`
	OrganizationSlug string `json:"organizationSlug,omitempty"`
}

type AzureAuthLoginRequest struct {
	IdentityID       string `json:"identityId"`
	JWT              string `json:"jwt"`
	OrganizationSlug string `json:"organizationSlug,omitempty"`
}

type AwsIamAuthLoginRequest struct {
	HTTPRequestMethod string `json:"iamHttpRequestMethod"`
	IamRequestBody    string `json:"iamRequestBody"`
	IamRequestHeaders string `json:"iamRequestHeaders"`
	IdentityId        string `json:"identityId"`
	OrganizationSlug  string `json:"organizationSlug,omitempty"`
}

type GCPAuthLoginRequest struct {
	IdentityID       string `json:"identityId"`
	JWT              string `json:"jwt"`
	OrganizationSlug string `json:"organizationSlug,omitempty"`
}

type OidcAuthLoginRequest struct {
	IdentityID       string `json:"identityId"`
	JWT              string `json:"jwt"`
	OrganizationSlug string `json:"organizationSlug,omitempty"`
}

type MachineIdentityAuthLoginResponse struct {
	AccessToken       string `json:"accessToken"`
	ExpiresIn         int64  `json:"expiresIn"`
	AccessTokenMaxTTL int64  `json:"accessTokenMaxTTL"`
	TokenType         string `json:"tokenType"`
}

type RenewAccessTokenRequest struct {
	AccessToken string `json:"accessToken"`
}

type OciAuthLoginRequest struct {
	IdentityID       string            `json:"identityId"`
	UserOcid         string            `json:"userOcid"`
	Headers          map[string]string `json:"headers"`
	OrganizationSlug string            `json:"organizationSlug,omitempty"`
}

type LdapAuthLoginRequest struct {
	IdentityID       string `json:"identityId"`
	Username         string `json:"username"`
	Password         string `json:"password"`
	OrganizationSlug string `json:"organizationSlug,omitempty"`
}
