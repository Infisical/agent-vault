package api

import (
	"github.com/go-resty/resty/v2"
	"github.com/infisical/go-sdk/packages/errors"
)

const callListDynamicSecretLeaseV1Operation = "CallListDynamicSecretLeaseV1"

func CallListDynamicSecretLeaseV1(httpClient *resty.Client, request ListDynamicSecretLeaseV1Request) (ListDynamicSecretLeaseV1Response, error) {

	listResponse := ListDynamicSecretLeaseV1Response{}

	req := httpClient.R().
		SetResult(&listResponse).
		SetQueryParams(map[string]string{
			"projectSlug":     request.ProjectSlug,
			"environmentSlug": request.EnvironmentSlug,
			"path":            request.SecretPath,
		})

	res, err := req.Get("/v1/dynamic-secrets/" + request.DynamicSecretName + "/leases")

	if err != nil {
		return ListDynamicSecretLeaseV1Response{}, errors.NewRequestError(callListDynamicSecretLeaseV1Operation, err)
	}

	if res.IsError() {
		return ListDynamicSecretLeaseV1Response{}, errors.NewAPIErrorWithResponse(callListDynamicSecretLeaseV1Operation, res)
	}

	return listResponse, nil
}
