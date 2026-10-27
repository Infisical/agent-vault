package api

import (
	"github.com/infisical/go-sdk/packages/util"
)

type SignSshPublicKeyV1Request struct {
	CertificateTemplateID string           `json:"certificateTemplateId"`
	PublicKey             string           `json:"publicKey"`
	CertType              util.SshCertType `json:"certType,omitempty"`
	Principals            []string         `json:"principals"`
	TTL                   string           `json:"ttl,omitempty"`
	KeyID                 string           `json:"keyId,omitempty"`
}

type SignSshPublicKeyV1Response struct {
	SerialNumber string `json:"serialNumber"`
	SignedKey    string `json:"signedKey"`
}

type IssueSshCredsV1Request struct {
	CertificateTemplateID string                `json:"certificateTemplateId"`
	KeyAlgorithm          util.CertKeyAlgorithm `json:"keyAlgorithm,omitempty"`
	CertType              util.SshCertType      `json:"certType,omitempty"`
	Principals            []string              `json:"principals"`
	TTL                   string                `json:"ttl,omitempty"`
	KeyID                 string                `json:"keyId,omitempty"`
}

type IssueSshCredsV1Response struct {
	SerialNumber string                `json:"serialNumber"`
	SignedKey    string                `json:"signedKey"`
	PrivateKey   string                `json:"privateKey"`
	PublicKey    string                `json:"publicKey"`
	KeyAlgorithm util.CertKeyAlgorithm `json:"keyAlgorithm"`
}

type GetSshHostsV1Request struct{}

type AllowedPrincipals struct {
	Usernames []string `json:"usernames"`
}

type SshHostLoginMapping struct {
	LoginUser         string            `json:"loginUser"`
	AllowedPrincipals AllowedPrincipals `json:"allowedPrincipals"`
}

type SshHost struct {
	ID            string                `json:"id"`
	ProjectID     string                `json:"projectId"`
	Hostname      string                `json:"hostname"`
	Alias         string                `json:"alias,omitempty"`
	UserCertTtl   string                `json:"userCertTtl"`
	HostCertTtl   string                `json:"hostCertTtl"`
	UserSshCaId   string                `json:"userSshCaId"`
	HostSshCaId   string                `json:"hostSshCaId"`
	LoginMappings []SshHostLoginMapping `json:"loginMappings"`
}

type GetSshHostsV1Response []SshHost

type IssueSshHostUserCertV1Request struct {
	LoginUser string `json:"loginUser"`
}

type IssueSshHostUserCertV1Response struct {
	SerialNumber string                `json:"serialNumber"`
	SignedKey    string                `json:"signedKey"`
	PrivateKey   string                `json:"privateKey"`
	PublicKey    string                `json:"publicKey"`
	KeyAlgorithm util.CertKeyAlgorithm `json:"keyAlgorithm"`
}

type IssueSshHostHostCertV1Request struct {
	PublicKey string `json:"publicKey"`
}

type IssueSshHostHostCertV1Response struct {
	SerialNumber string `json:"serialNumber"`
	SignedKey    string `json:"signedKey"`
}

type AddSshHostV1Request struct {
	ProjectID     string                `json:"projectId"`
	Hostname      string                `json:"hostname"`
	Alias         string                `json:"alias,omitempty"`
	UserCertTtl   string                `json:"userCertTtl,omitempty"`
	HostCertTtl   string                `json:"hostCertTtl,omitempty"`
	UserSshCaId   string                `json:"userSshCaId,omitempty"`
	HostSshCaId   string                `json:"hostSshCaId,omitempty"`
	LoginMappings []SshHostLoginMapping `json:"loginMappings,omitempty"`
}

type AddSshHostV1Response SshHost
