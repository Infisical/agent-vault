package api

import (
	"github.com/go-resty/resty/v2"
	"github.com/infisical/go-sdk/packages/errors"
)

const callOidcAuthLoginOperation = "CallOidcAuthLogin"

func CallOidcAuthLogin(httpClient *resty.Client, request OidcAuthLoginRequest) (credential MachineIdentityAuthLoginResponse, e error) {
	var responseData MachineIdentityAuthLoginResponse

	clonedClient := httpClient.Clone()
	clonedClient.SetAuthToken("")
	clonedClient.SetAuthScheme("")

	response, err := clonedClient.R().
		SetResult(&responseData).
		SetBody(request).
		Post("/v1/auth/oidc-auth/login")

	if err != nil {
		return MachineIdentityAuthLoginResponse{}, errors.NewRequestError(callOidcAuthLoginOperation, err)
	}

	if response.IsError() {
		return MachineIdentityAuthLoginResponse{}, errors.NewAPIErrorWithResponse(callOidcAuthLoginOperation, response)
	}

	return responseData, nil
}
