package api

import (
	"github.com/go-resty/resty/v2"
	"github.com/infisical/go-sdk/packages/errors"
)

const callJwtAuthLoginOperation = "CallJwtAuthLogin"

func CallJwtAuthLogin(httpClient *resty.Client, request JwtAuthLoginRequest) (credential MachineIdentityAuthLoginResponse, e error) {
	var responseData MachineIdentityAuthLoginResponse

	clonedClient := httpClient.Clone()
	clonedClient.SetAuthToken("")
	clonedClient.SetAuthScheme("")

	response, err := clonedClient.R().
		SetResult(&responseData).
		SetBody(request).
		Post("/v1/auth/jwt-auth/login")

	if err != nil {
		return responseData, errors.NewRequestError(callJwtAuthLoginOperation, err)
	}

	if response.IsError() {
		return responseData, errors.NewAPIErrorWithResponse(callJwtAuthLoginOperation, response)
	}

	return responseData, nil
}
