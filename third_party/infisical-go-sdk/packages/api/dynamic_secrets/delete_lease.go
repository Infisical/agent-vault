package api

import (
	"github.com/go-resty/resty/v2"
	"github.com/infisical/go-sdk/packages/errors"
)

const callDeleteDynamicSecretLeaseV1Operation = "CallDeleteDynamicSecretLeaseV1"

func CallDeleteDynamicSecretLeaseV1(httpClient *resty.Client, request DeleteDynamicSecretLeaseV1Request) (DeleteDynamicSecretLeaseV1Response, error) {

	deleteResponse := DeleteDynamicSecretLeaseV1Response{}

	req := httpClient.R().
		SetResult(&deleteResponse).
		SetBody(request)

	res, err := req.Delete("/v1/dynamic-secrets/leases/" + request.LeaseId)

	if err != nil {
		return DeleteDynamicSecretLeaseV1Response{}, errors.NewRequestError(callDeleteDynamicSecretLeaseV1Operation, err)
	}

	if res.IsError() {
		return DeleteDynamicSecretLeaseV1Response{}, errors.NewAPIErrorWithResponse(callDeleteDynamicSecretLeaseV1Operation, res)
	}

	return deleteResponse, nil
}
