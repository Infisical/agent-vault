package api

import (
	"fmt"

	"github.com/go-resty/resty/v2"
	"github.com/infisical/go-sdk/packages/errors"
)

const callCreateSecretV3RawOperation = "CallCreateSecretV3Raw"

func CallCreateSecretV3(httpClient *resty.Client, request CreateSecretV3RawRequest) (CreateSecretV3RawResponse, error) {

	createResponse := CreateSecretV3RawResponse{}

	req := httpClient.R().
		SetResult(&createResponse).
		SetBody(request)

	res, err := req.Post(fmt.Sprintf("/v3/secrets/raw/%s", request.SecretKey))

	if err != nil {
		return CreateSecretV3RawResponse{}, errors.NewRequestError(callCreateSecretV3RawOperation, err)
	}

	if res.IsError() {
		return CreateSecretV3RawResponse{}, errors.NewAPIErrorWithResponse(callCreateSecretV3RawOperation, res)
	}

	return createResponse, nil
}
