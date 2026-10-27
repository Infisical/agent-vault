package api

import (
	"github.com/go-resty/resty/v2"
	"github.com/infisical/go-sdk/packages/errors"
)

const callAWSIamAuthLoginOperation = "CallAWSIamAuthLogin"

func CallAWSIamAuthLogin(httpClient *resty.Client, request AwsIamAuthLoginRequest) (credential MachineIdentityAuthLoginResponse, e error) {
	var responseData MachineIdentityAuthLoginResponse

	clonedClient := httpClient.Clone()
	clonedClient.SetAuthToken("")
	clonedClient.SetAuthScheme("")

	response, err := clonedClient.R().
		SetResult(&responseData).
		SetBody(request).
		Post("/v1/auth/aws-auth/login")

	if err != nil {
		return MachineIdentityAuthLoginResponse{}, errors.NewRequestError(callAWSIamAuthLoginOperation, err)
	}

	if response.IsError() {
		return MachineIdentityAuthLoginResponse{}, errors.NewAPIErrorWithResponse(callAWSIamAuthLoginOperation, response)
	}

	return responseData, nil
}
