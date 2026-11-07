package api

import (
	"github.com/go-resty/resty/v2"
	"github.com/infisical/go-sdk/packages/errors"
)

const callRenewDynamicSecretLeaseV1Operation = "CallRenewDynamicSecretLeaseV1"

func CallRenewDynamicSecretLeaseV1(httpClient *resty.Client, request RenewDynamicSecretLeaseV1Request) (RenewDynamicSecretLeaseV1Response, error) {

	renewResponse := RenewDynamicSecretLeaseV1Response{}

	req := httpClient.R().
		SetResult(&renewResponse).
		SetBody(request)

	res, err := req.Post("/v1/dynamic-secrets/leases/" + request.LeaseId + "/renew")

	if err != nil {
		return RenewDynamicSecretLeaseV1Response{}, errors.NewRequestError(callRenewDynamicSecretLeaseV1Operation, err)
	}

	if res.IsError() {
		return RenewDynamicSecretLeaseV1Response{}, errors.NewAPIErrorWithResponse(callRenewDynamicSecretLeaseV1Operation, res)
	}

	return renewResponse, nil
}
