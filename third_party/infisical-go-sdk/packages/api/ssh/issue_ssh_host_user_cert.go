package api

import (
	"fmt"

	"github.com/go-resty/resty/v2"
	"github.com/infisical/go-sdk/packages/errors"
)

const callIssueSshHostUserCertOperation = "CallIssueSshHostUserCertV1"

func CallIssueSshHostUserCertV1(httpClient *resty.Client, sshHostId string, body IssueSshHostUserCertV1Request) (IssueSshHostUserCertV1Response, error) {
	resp := IssueSshHostUserCertV1Response{}

	res, err := httpClient.R().
		SetBody(body).
		SetResult(&resp).
		Post(fmt.Sprintf("/v1/ssh/hosts/%s/issue-user-cert", sshHostId))

	if err != nil {
		return IssueSshHostUserCertV1Response{}, errors.NewRequestError(callIssueSshHostUserCertOperation, err)
	}

	if res.IsError() {
		return IssueSshHostUserCertV1Response{}, errors.NewAPIErrorWithResponse(callIssueSshHostUserCertOperation, res)
	}

	return resp, nil
}
