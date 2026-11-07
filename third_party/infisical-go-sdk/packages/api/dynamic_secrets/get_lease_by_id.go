package api

import (
	"github.com/go-resty/resty/v2"
	"github.com/infisical/go-sdk/packages/errors"
)

const callGetDynamicSecretLeaseByIdV1Operation = "CallGetDynamicSecretLeaseByIdV1"

func CallGetByDynamicSecretByIdLeaseV1(httpClient *resty.Client, request GetDynamicSecretLeaseByIdV1Request) (GetDynamicSecretLeaseByIdV1Response, error) {

	getByIdResponse := GetDynamicSecretLeaseByIdV1Response{}

	req := httpClient.R().
		SetResult(&getByIdResponse).
		SetQueryParams(map[string]string{
			"projectSlug":     request.ProjectSlug,
			"environmentSlug": request.EnvironmentSlug,
			"path":            request.SecretPath,
		})

	res, err := req.Get("/v1/dynamic-secrets/leases/" + request.LeaseId)

	if err != nil {
		return GetDynamicSecretLeaseByIdV1Response{}, errors.NewRequestError(callGetDynamicSecretLeaseByIdV1Operation, err)
	}

	if res.IsError() {
		return GetDynamicSecretLeaseByIdV1Response{}, errors.NewAPIErrorWithResponse(callGetDynamicSecretLeaseByIdV1Operation, res)
	}

	return getByIdResponse, nil
}
