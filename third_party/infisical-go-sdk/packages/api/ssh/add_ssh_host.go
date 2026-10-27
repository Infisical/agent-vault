package api

import (
	"github.com/go-resty/resty/v2"
	"github.com/infisical/go-sdk/packages/errors"
)

const callAddSshHostOperation = "CallAddSshHostV1"

func CallAddSshHostV1(httpClient *resty.Client, body AddSshHostV1Request) (AddSshHostV1Response, error) {
	resp := AddSshHostV1Response{}

	res, err := httpClient.R().
		SetBody(body).
		SetResult(&resp).
		Post("/v1/ssh/hosts")

	if err != nil {
		return AddSshHostV1Response{}, errors.NewRequestError(callAddSshHostOperation, err)
	}

	if res.IsError() {
		return AddSshHostV1Response{}, errors.NewAPIErrorWithResponse(callAddSshHostOperation, res)
	}

	return resp, nil
}
