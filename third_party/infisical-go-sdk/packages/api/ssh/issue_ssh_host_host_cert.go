package api

import (
	"fmt"

	"github.com/go-resty/resty/v2"
	"github.com/infisical/go-sdk/packages/errors"
)

const callIssueSshHostHostCertOperation = "CallIssueSshHostHostCertV1"

func CallIssueSshHostHostCertV1(httpClient *resty.Client, sshHostId string, body IssueSshHostHostCertV1Request) (IssueSshHostHostCertV1Response, error) {
	resp := IssueSshHostHostCertV1Response{}

	res, err := httpClient.R().
		SetBody(body).
		SetResult(&resp).
		Post(fmt.Sprintf("/v1/ssh/hosts/%s/issue-host-cert", sshHostId))

	if err != nil {
		return IssueSshHostHostCertV1Response{}, errors.NewRequestError(callIssueSshHostHostCertOperation, err)
	}

	if res.IsError() {
		return IssueSshHostHostCertV1Response{}, errors.NewAPIErrorWithResponse(callIssueSshHostHostCertOperation, res)
	}

	return resp, nil
}
