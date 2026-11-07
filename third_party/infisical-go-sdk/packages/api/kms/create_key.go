package api

import (
	"github.com/go-resty/resty/v2"
	"github.com/infisical/go-sdk/packages/errors"
)

const callKmsCreateKeyOperationV1 = "CallKmsCreateKeyV1"

func CallKmsCreateKeyV1(httpClient *resty.Client, request KmsCreateKeyV1Request) (KmsCreateKeyV1Response, error) {
	kmsCreateKeyResponse := KmsCreateKeyV1Response{}

	res, err := httpClient.R().
		SetResult(&kmsCreateKeyResponse).
		SetBody(request).
		Post("/v1/kms/keys")

	if err != nil {
		return KmsCreateKeyV1Response{}, errors.NewRequestError(callKmsCreateKeyOperationV1, err)
	}

	if res.IsError() {
		return KmsCreateKeyV1Response{}, errors.NewAPIErrorWithResponse(callKmsCreateKeyOperationV1, res)
	}

	return kmsCreateKeyResponse, nil
}
