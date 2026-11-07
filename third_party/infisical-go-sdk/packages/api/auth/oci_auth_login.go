package api

import (
	"github.com/go-resty/resty/v2"
	"github.com/infisical/go-sdk/packages/errors"
)

const callOciAuthLoginOperation = "CallOciAuthLogin"

func CallOciAuthLogin(httpClient *resty.Client, request OciAuthLoginRequest) (credential MachineIdentityAuthLoginResponse, e error) {
	var responseData MachineIdentityAuthLoginResponse

	clonedClient := httpClient.Clone()
	clonedClient.SetAuthToken("")
	clonedClient.SetAuthScheme("")

	response, err := clonedClient.R().
		SetResult(&responseData).
		SetBody(request).
		Post("/v1/auth/oci-auth/login")

	if err != nil {
		return MachineIdentityAuthLoginResponse{}, errors.NewRequestError(callOciAuthLoginOperation, err)
	}

	if response.IsError() {
		return MachineIdentityAuthLoginResponse{}, errors.NewAPIErrorWithResponse(callOciAuthLoginOperation, response)
	}

	return responseData, nil
}
