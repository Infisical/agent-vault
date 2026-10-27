package api

import (
	"fmt"

	"github.com/go-resty/resty/v2"
	"github.com/infisical/go-sdk/packages/errors"
)

const callKmsSignDataOperationV1 = "CallKmsSignDataV1"

func CallKmsSignDataV1(httpClient *resty.Client, request KmsSignDataV1Request) (KmsSignDataV1Response, error) {
	kmsSignDataResponse := KmsSignDataV1Response{}

	res, err := httpClient.R().
		SetResult(&kmsSignDataResponse).
		SetBody(request).
		Post(fmt.Sprintf("/v1/kms/keys/%s/sign", request.KeyId))

	if err != nil {
		return KmsSignDataV1Response{}, errors.NewRequestError(callKmsSignDataOperationV1, err)
	}

	if res.IsError() {
		return KmsSignDataV1Response{}, errors.NewAPIErrorWithResponse(callKmsSignDataOperationV1, res)
	}

	return kmsSignDataResponse, nil
}
