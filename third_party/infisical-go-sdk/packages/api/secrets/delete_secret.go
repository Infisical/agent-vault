package api

import (
	"fmt"

	"github.com/go-resty/resty/v2"
	"github.com/infisical/go-sdk/packages/errors"
)

const callDeleteSecretV3RawOperation = "CallDeleteSecretV3Raw"

func CallDeleteSecretV3(httpClient *resty.Client, request DeleteSecretV3RawRequest) (DeleteSecretV3RawResponse, error) {

	deleteResponse := DeleteSecretV3RawResponse{}

	req := httpClient.R().
		SetResult(&deleteResponse).
		SetBody(request)

	res, err := req.Delete(fmt.Sprintf("/v3/secrets/raw/%s", request.SecretKey))

	if err != nil {
		return DeleteSecretV3RawResponse{}, errors.NewRequestError(callDeleteSecretV3RawOperation, err)
	}

	if res.IsError() {
		return DeleteSecretV3RawResponse{}, errors.NewAPIErrorWithResponse(callDeleteSecretV3RawOperation, res)
	}

	return deleteResponse, nil
}
