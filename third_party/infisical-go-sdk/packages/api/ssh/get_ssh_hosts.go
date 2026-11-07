package api

import (
	"github.com/go-resty/resty/v2"
	"github.com/infisical/go-sdk/packages/errors"
)

const callGetSshHostsOperation = "CallGetSshHostsV1"

func GetSshHostsV1(httpClient *resty.Client, _ GetSshHostsV1Request) (GetSshHostsV1Response, error) {
	var getSshHostsResponse GetSshHostsV1Response

	res, err := httpClient.R().
		SetResult(&getSshHostsResponse).
		Get("/v1/ssh/hosts")

	if err != nil {
		return nil, errors.NewRequestError(callGetSshHostsOperation, err)
	}

	if res.IsError() {
		return nil, errors.NewAPIErrorWithResponse(callGetSshHostsOperation, res)
	}

	return getSshHostsResponse, nil
}
