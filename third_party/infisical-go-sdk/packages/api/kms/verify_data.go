package api

import (
	"fmt"

	"github.com/go-resty/resty/v2"
	"github.com/infisical/go-sdk/packages/errors"
)

const callKmsVerifyDataOperationV1 = "CallKmsVerifyDataV1"

func CallKmsVerifyDataV1(httpClient *resty.Client, request KmsVerifyDataV1Request) (KmsVerifyDataV1Response, error) {
	kmsVerifyDataResponse := KmsVerifyDataV1Response{}

	res, err := httpClient.R().
		SetResult(&kmsVerifyDataResponse).
		SetBody(request).
		Post(fmt.Sprintf("/v1/kms/keys/%s/verify", request.KeyId))

	if err != nil {
		return KmsVerifyDataV1Response{}, errors.NewRequestError(callKmsVerifyDataOperationV1, err)
	}

	if res.IsError() {
		return KmsVerifyDataV1Response{}, errors.NewAPIErrorWithResponse(callKmsVerifyDataOperationV1, res)
	}

	return kmsVerifyDataResponse, nil
}
