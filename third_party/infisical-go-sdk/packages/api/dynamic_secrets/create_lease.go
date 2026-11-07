package api

import (
	"github.com/go-resty/resty/v2"
	"github.com/infisical/go-sdk/packages/errors"
)

const callCreateDynamicSecretLeaseV1Operation = "CallCreateDynamicSecretLeaseV1"

func CallCreateDynamicSecretLeaseV1(httpClient *resty.Client, request CreateDynamicSecretLeaseV1Request) (CreateDynamicSecretLeaseV1Response, error) {

	createResponse := CreateDynamicSecretLeaseV1Response{}

	req := httpClient.R().
		SetResult(&createResponse).
		SetBody(request)

	res, err := req.Post("/v1/dynamic-secrets/leases")

	if err != nil {
		return CreateDynamicSecretLeaseV1Response{}, errors.NewRequestError(callCreateDynamicSecretLeaseV1Operation, err)
	}

	if res.IsError() {
		return CreateDynamicSecretLeaseV1Response{}, errors.NewAPIErrorWithResponse(callCreateDynamicSecretLeaseV1Operation, res)
	}

	return createResponse, nil
}
