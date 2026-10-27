package api

import (
	"fmt"

	"github.com/go-resty/resty/v2"

	"github.com/infisical/go-sdk/packages/errors"
)

const callKmsGetSigningAlgorithmsOperationV1 = "CallKmsGetSigningAlgorithmsV1"

func CallKmsGetSigningAlgorithmsV1(httpClient *resty.Client, request KmsListSigningAlgorithmsV1Request) (KmsListSigningAlgorithmsV1Response, error) {
	kmsListSigningAlgorithmsResponse := KmsListSigningAlgorithmsV1Response{}

	res, err := httpClient.R().
		SetResult(&kmsListSigningAlgorithmsResponse).
		Get(fmt.Sprintf("/v1/kms/keys/%s/signing-algorithms", request.KeyId))

	if err != nil {
		return KmsListSigningAlgorithmsV1Response{}, errors.NewRequestError(callKmsGetSigningAlgorithmsOperationV1, err)
	}

	if res.IsError() {
		return KmsListSigningAlgorithmsV1Response{}, errors.NewAPIErrorWithResponse(callKmsGetSigningAlgorithmsOperationV1, res)
	}

	return kmsListSigningAlgorithmsResponse, nil
}
