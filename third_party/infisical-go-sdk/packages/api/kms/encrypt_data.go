package api

import (
	"fmt"

	"github.com/go-resty/resty/v2"
	"github.com/infisical/go-sdk/packages/errors"
)

const callKmsEncryptDataOperationV1 = "CallKmsEncryptDataV1"

func CallKmsEncryptDataV1(httpClient *resty.Client, request KmsEncryptDataV1Request) (KmsEncryptDataV1Response, error) {
	kmsEncryptDataResponse := KmsEncryptDataV1Response{}

	res, err := httpClient.R().
		SetResult(&kmsEncryptDataResponse).
		SetBody(request).
		Post(fmt.Sprintf("/v1/kms/keys/%s/encrypt", request.KeyId))

	if err != nil {
		return KmsEncryptDataV1Response{}, errors.NewRequestError(callKmsEncryptDataOperationV1, err)
	}

	if res.IsError() {
		return KmsEncryptDataV1Response{}, errors.NewAPIErrorWithResponse(callKmsEncryptDataOperationV1, res)
	}

	return kmsEncryptDataResponse, nil
}
