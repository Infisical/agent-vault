package api

import (
	"github.com/go-resty/resty/v2"
	"github.com/infisical/go-sdk/packages/errors"
)

const callRenewAccessToken = "CallRenewAccessToken"

func CallRenewAccessToken(httpClient *resty.Client, request RenewAccessTokenRequest) (credential MachineIdentityAuthLoginResponse, e error) {
	var responseData MachineIdentityAuthLoginResponse

	clonedClient := httpClient.Clone()
	clonedClient.SetAuthToken("")
	clonedClient.SetAuthScheme("")

	response, err := clonedClient.R().
		SetResult(&responseData).
		SetBody(request).
		Post("/v1/auth/token/renew")

	if err != nil {
		return responseData, errors.NewRequestError(callRenewAccessToken, err)
	}

	if response.IsError() {
		return responseData, errors.NewAPIErrorWithResponse(callRenewAccessToken, response)
	}

	return responseData, nil
}
