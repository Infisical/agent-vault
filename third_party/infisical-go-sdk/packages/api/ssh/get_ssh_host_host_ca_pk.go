package api

import (
	"github.com/go-resty/resty/v2"
	"github.com/infisical/go-sdk/packages/errors"
)

func GetSshHostHostCaPublicKeyV1(httpClient *resty.Client, sshHostId string) (string, error) {
	res, err := httpClient.R().
		Get("/v1/ssh/hosts/" + sshHostId + "/host-ca-public-key")

	if err != nil {
		return "", errors.NewRequestError("GetSshHostHostCaPublicKeyV1", err)
	}

	if res.IsError() {
		return "", errors.NewAPIErrorWithResponse("GetSshHostHostCaPublicKeyV1", res)
	}

	return res.String(), nil
}
