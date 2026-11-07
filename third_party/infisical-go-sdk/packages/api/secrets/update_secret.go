package api

import (
	"fmt"

	"github.com/go-resty/resty/v2"
	"github.com/infisical/go-sdk/packages/errors"
)

const callUpdateSecretV3RawOperation = "CallUpdateSecretV3Raw"

func CallUpdateSecretV3(httpClient *resty.Client, request UpdateSecretV3RawRequest) (UpdateSecretV3RawResponse, error) {

	updateResponse := UpdateSecretV3RawResponse{}

	req := httpClient.R().
		SetResult(&updateResponse).
		SetBody(request)

	res, err := req.Patch(fmt.Sprintf("/v3/secrets/raw/%s", request.SecretKey))

	if err != nil {
		return UpdateSecretV3RawResponse{}, errors.NewRequestError(callUpdateSecretV3RawOperation, err)
	}

	if res.IsError() {
		return UpdateSecretV3RawResponse{}, errors.NewAPIErrorWithResponse(callUpdateSecretV3RawOperation, res)
	}

	return updateResponse, nil
}
