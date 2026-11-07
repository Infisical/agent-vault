package api

import (
	"fmt"

	"github.com/go-resty/resty/v2"
	"github.com/infisical/go-sdk/packages/errors"
)

const callKmsDecryptDataOperationV1 = "CallKmsDecryptDataV1"

func CallKmsDecryptDataV1(httpClient *resty.Client, request KmsDecryptDataV1Request) (KmsDecryptDataV1Response, error) {
	kmsDecryptDataResponse := KmsDecryptDataV1Response{}

	res, err := httpClient.R().
		SetResult(&kmsDecryptDataResponse).
		SetBody(request).
		Post(fmt.Sprintf("/v1/kms/keys/%s/decrypt", request.KeyId))

	if err != nil {
		return KmsDecryptDataV1Response{}, errors.NewRequestError(callKmsDecryptDataOperationV1, err)
	}

	if res.IsError() {
		return KmsDecryptDataV1Response{}, errors.NewAPIErrorWithResponse(callKmsDecryptDataOperationV1, res)
	}

	return kmsDecryptDataResponse, nil
}
