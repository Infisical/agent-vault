package api

import (
	"fmt"

	"github.com/go-resty/resty/v2"
	"github.com/infisical/go-sdk/packages/errors"
)

const callKmsGetPublicKeyOperationV1 = "CallKmsGetPublicKeyV1"

func CallKmsGetPublicKeyV1(httpClient *resty.Client, request KmsGetPublicKeyV1Request) (KmsGetPublicKeyV1Response, error) {
	kmsGetPublicKeyResponse := KmsGetPublicKeyV1Response{}

	res, err := httpClient.R().
		SetResult(&kmsGetPublicKeyResponse).
		Get(fmt.Sprintf("/v1/kms/keys/%s/public-key", request.KeyId))

	if err != nil {
		return KmsGetPublicKeyV1Response{}, errors.NewRequestError(callKmsGetPublicKeyOperationV1, err)
	}

	if res.IsError() {
		return KmsGetPublicKeyV1Response{}, errors.NewAPIErrorWithResponse(callKmsGetPublicKeyOperationV1, res)
	}

	return kmsGetPublicKeyResponse, nil
}
