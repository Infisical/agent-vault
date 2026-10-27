package api

import (
	"github.com/go-resty/resty/v2"
	"github.com/infisical/go-sdk/packages/errors"
)

const callBatchCreateSecretV3RawOperation = "CallBatchCreateSecretV3Raw"

func CallBatchCreateSecretV3(httpClient *resty.Client, request BatchCreateSecretsV3RawRequest) (BatchCreateSecretsV3RawResponse, error) {

	createBatchResponse := BatchCreateSecretsV3RawResponse{}

	req := httpClient.R().
		SetResult(&createBatchResponse).
		SetBody(request)

	res, err := req.Post("/v3/secrets/batch/raw")

	if err != nil {
		return BatchCreateSecretsV3RawResponse{}, errors.NewRequestError(callBatchCreateSecretV3RawOperation, err)
	}

	if res.IsError() {
		return BatchCreateSecretsV3RawResponse{}, errors.NewAPIErrorWithResponse(callBatchCreateSecretV3RawOperation, res)
	}

	for idx := range createBatchResponse.Secrets {

		secretPath := request.SecretPath

		if secretPath == "" {
			secretPath = "/"
		}

		createBatchResponse.Secrets[idx].SecretPath = secretPath
	}

	return createBatchResponse, nil
}
