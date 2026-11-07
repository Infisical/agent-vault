package api

import (
	"fmt"

	"github.com/go-resty/resty/v2"
	"github.com/infisical/go-sdk/packages/errors"
)

const callKmsDeleteKeyOperationV1 = "CallKmsDeleteKeyV1"

func CallKmsDeleteKeyV1(httpClient *resty.Client, request KmsDeleteKeyV1Request) (KmsDeleteKeyV1Response, error) {
	kmsDeleteKeyResponse := KmsDeleteKeyV1Response{}

	res, err := httpClient.R().
		SetResult(&kmsDeleteKeyResponse).
		SetBody(request).
		Delete(fmt.Sprintf("/v1/kms/keys/%s", request.KeyId))

	if err != nil {
		return KmsDeleteKeyV1Response{}, errors.NewRequestError(callKmsDeleteKeyOperationV1, err)
	}

	if res.IsError() {
		return KmsDeleteKeyV1Response{}, errors.NewAPIErrorWithResponse(callKmsDeleteKeyOperationV1, res)
	}

	return kmsDeleteKeyResponse, nil
}
