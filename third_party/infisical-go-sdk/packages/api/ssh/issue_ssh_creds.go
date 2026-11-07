package api

import (
	"github.com/go-resty/resty/v2"
	"github.com/infisical/go-sdk/packages/errors"
)

const callIssueSshCredsOperation = "CallIssueSshCredsV1"

func CallIssueSshCredsV1(httpClient *resty.Client, request IssueSshCredsV1Request) (IssueSshCredsV1Response, error) {
	issueSshCredsResponse := IssueSshCredsV1Response{}

	res, err := httpClient.R().
		SetResult(&issueSshCredsResponse).
		SetBody(request).
		Post("/v1/ssh/certificates/issue")

	if err != nil {
		return IssueSshCredsV1Response{}, errors.NewRequestError(callIssueSshCredsOperation, err)
	}

	if res.IsError() {
		return IssueSshCredsV1Response{}, errors.NewAPIErrorWithResponse(callIssueSshCredsOperation, res)
	}

	return issueSshCredsResponse, nil
}
