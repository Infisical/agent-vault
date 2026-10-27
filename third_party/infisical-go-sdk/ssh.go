package infisical

import (
	api "github.com/infisical/go-sdk/packages/api/ssh"
)

type SignSshPublicKeyOptions = api.SignSshPublicKeyV1Request
type IssueSshCredsOptions = api.IssueSshCredsV1Request
type GetSshHostsOptions = api.GetSshHostsV1Request
type IssueSshHostUserCertOptions = api.IssueSshHostUserCertV1Request
type IssueSshHostHostCertOptions = api.IssueSshHostHostCertV1Request
type AddSshHostOptions = api.AddSshHostV1Request

type SshInterface interface {
	SignKey(options SignSshPublicKeyOptions) (api.SignSshPublicKeyV1Response, error)
	IssueCredentials(options IssueSshCredsOptions) (api.IssueSshCredsV1Response, error)
	GetSshHosts(options GetSshHostsOptions) (api.GetSshHostsV1Response, error)
	GetSshHostUserCaPublicKey(sshHostId string) (string, error)
	GetSshHostHostCaPublicKey(sshHostId string) (string, error)
	IssueSshHostUserCert(sshHostId string, options IssueSshHostUserCertOptions) (api.IssueSshHostUserCertV1Response, error)
	IssueSshHostHostCert(sshHostId string, options IssueSshHostHostCertOptions) (api.IssueSshHostHostCertV1Response, error)
	AddSshHost(options AddSshHostOptions) (api.AddSshHostV1Response, error)
}

type Ssh struct {
	client *InfisicalClient
}

func (f *Ssh) SignKey(options SignSshPublicKeyOptions) (api.SignSshPublicKeyV1Response, error) {
	res, err := api.CallSignSshPublicKeyV1(f.client.httpClient, options)

	if err != nil {
		return api.SignSshPublicKeyV1Response{}, err
	}

	return res, nil
}

func (f *Ssh) IssueCredentials(options IssueSshCredsOptions) (api.IssueSshCredsV1Response, error) {
	res, err := api.CallIssueSshCredsV1(f.client.httpClient, options)

	if err != nil {
		return api.IssueSshCredsV1Response{}, err
	}

	return res, nil
}

func (f *Ssh) GetSshHosts(options GetSshHostsOptions) (api.GetSshHostsV1Response, error) {
	res, err := api.GetSshHostsV1(f.client.httpClient, options)

	if err != nil {
		return api.GetSshHostsV1Response{}, err
	}

	return res, nil
}

func (f *Ssh) GetSshHostUserCaPublicKey(sshHostId string) (string, error) {
	res, err := api.GetSshHostUserCaPublicKeyV1(f.client.httpClient, sshHostId)

	if err != nil {
		return "", err
	}

	return res, nil
}

func (f *Ssh) GetSshHostHostCaPublicKey(sshHostId string) (string, error) {
	res, err := api.GetSshHostHostCaPublicKeyV1(f.client.httpClient, sshHostId)

	if err != nil {
		return "", err
	}

	return res, nil
}

func (f *Ssh) IssueSshHostUserCert(sshHostId string, options IssueSshHostUserCertOptions) (api.IssueSshHostUserCertV1Response, error) {
	res, err := api.CallIssueSshHostUserCertV1(f.client.httpClient, sshHostId, options)
	if err != nil {
		return api.IssueSshHostUserCertV1Response{}, err
	}
	return res, nil
}

func (f *Ssh) IssueSshHostHostCert(sshHostId string, options IssueSshHostHostCertOptions) (api.IssueSshHostHostCertV1Response, error) {
	res, err := api.CallIssueSshHostHostCertV1(f.client.httpClient, sshHostId, options)
	if err != nil {
		return api.IssueSshHostHostCertV1Response{}, err
	}
	return res, nil
}

func (f *Ssh) AddSshHost(options AddSshHostOptions) (api.AddSshHostV1Response, error) {
	res, err := api.CallAddSshHostV1(f.client.httpClient, options)
	if err != nil {
		return api.AddSshHostV1Response{}, err
	}
	return res, nil
}

func NewSsh(client *InfisicalClient) SshInterface {
	return &Ssh{client: client}
}
