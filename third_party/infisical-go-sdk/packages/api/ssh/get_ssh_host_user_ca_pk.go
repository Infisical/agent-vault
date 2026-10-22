package api

import (
	"github.com/go-resty/resty/v2"
	"github.com/infisical/go-sdk/packages/errors"
)

func GetSshHostUserCaPublicKeyV1(httpClient *resty.Client, sshHostId string) (string, error) {
	res, err := httpClient.R().
		Get("/v1/ssh/hosts/" + sshHostId + "/user-ca-public-key")

	if err != nil {
		return "", errors.NewRequestError("GetSshHostUserCaPublicKeyV1", err)
	}

	if res.IsError() {
		return "", errors.NewAPIErrorWithResponse("GetSshHostUserCaPublicKeyV1", res)
	}

	return res.String(), nil
}
