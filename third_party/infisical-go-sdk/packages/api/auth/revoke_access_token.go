package api

import (
	"github.com/go-resty/resty/v2"
	"github.com/infisical/go-sdk/packages/errors"
)

const callRevokeAccessTokenOperation = "CallRevokeAccessToken"

func CallRevokeAccessToken(httpClient *resty.Client, request RevokeAccessTokenRequest) (RevokeAccessTokenResponse, error) {
	var responseData RevokeAccessTokenResponse

	response, err := httpClient.R().
		SetResult(&responseData).
		SetBody(request).
		Post("/v1/auth/token/revoke")

	if err != nil {
		return responseData, errors.NewRequestError(callRevokeAccessTokenOperation, err)
	}

	if response.IsError() {
		return responseData, errors.NewAPIErrorWithResponse(callRevokeAccessTokenOperation, response)
	}

	return responseData, nil
}
