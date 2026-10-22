package api

import (
	"github.com/infisical/go-sdk/packages/models"
)

type CreateDynamicSecretLeaseV1Request struct {
	DynamicSecretName string         `json:"dynamicSecretName"`
	ProjectSlug       string         `json:"projectSlug"`
	TTL               string         `json:"ttl"`
	SecretPath        string         `json:"path"`
	EnvironmentSlug   string         `json:"environmentSlug"`
	Config            map[string]any `json:"config"`
}

type CreateDynamicSecretLeaseV1Response struct {
	Lease         models.DynamicSecretLease `json:"lease"`
	DynamicSecret models.DynamicSecret      `json:"dynamicSecret"`
	Data          map[string]any            `json:"data"`
}

type DeleteDynamicSecretLeaseV1Request struct {
	LeaseId         string `json:"leaseId"`
	ProjectSlug     string `json:"projectSlug"`
	SecretPath      string `json:"path"`
	EnvironmentSlug string `json:"environmentSlug"`
	IsForced        bool   `json:"isForced"`
}

type DeleteDynamicSecretLeaseV1Response struct {
	Lease models.DynamicSecretLease `json:"lease"`
}

type RenewDynamicSecretLeaseV1Request struct {
	LeaseId         string `json:"leaseId"`
	TTL             string `json:"ttl"`
	ProjectSlug     string `json:"projectSlug"`
	SecretPath      string `json:"path"`
	EnvironmentSlug string `json:"environmentSlug"`
	IsForced        bool   `json:"isForced"`
}

type RenewDynamicSecretLeaseV1Response struct {
	Lease models.DynamicSecretLease `json:"lease"`
}

type GetDynamicSecretLeaseByIdV1Request struct {
	LeaseId         string `json:"leaseId"`
	ProjectSlug     string `json:"projectSlug"`
	SecretPath      string `json:"path"`
	EnvironmentSlug string `json:"environmentSlug"`
}

type GetDynamicSecretLeaseByIdV1Response struct {
	Lease models.DynamicSecretLeaseWithDynamicSecret `json:"lease"`
}

type ListDynamicSecretLeaseV1Request struct {
	DynamicSecretName string `json:"secretName"`
	ProjectSlug       string `json:"projectSlug"`
	SecretPath        string `json:"path"`
	EnvironmentSlug   string `json:"environmentSlug"`
}

type ListDynamicSecretLeaseV1Response struct {
	Leases []models.DynamicSecretLease `json:"leases"`
}

type GetDynamicSecretByNameV1Request struct {
	DynamicSecretName string `json:"secretName"`
	ProjectSlug       string `json:"projectSlug"`
	SecretPath        string `json:"path"`
	EnvironmentSlug   string `json:"environmentSlug"`
}

type GetDynamicSecretByNameV1Response struct {
	DynamicSecret models.DynamicSecret `json:"dynamicSecret"`
}

type ListDynamicSecretsV1Request struct {
	ProjectSlug     string `json:"projectSlug"`
	SecretPath      string `json:"path"`
	EnvironmentSlug string `json:"environmentSlug"`
}

type ListDynamicSecretsV1Response struct {
	DynamicSecrets []models.DynamicSecret `json:"dynamicSecrets"`
}
