package api

import (
	"github.com/go-resty/resty/v2"
	"github.com/infisical/go-sdk/packages/errors"
)

const callGetDynamicSecretByNameV1Operation = "CallGetDynamicSecretSecretByNameV1"

func CallGetDynamicSecretByNameV1(httpClient *resty.Client, request GetDynamicSecretByNameV1Request) (GetDynamicSecretByNameV1Response, error) {

	getByNameResponse := GetDynamicSecretByNameV1Response{}

	req := httpClient.R().
		SetResult(&getByNameResponse).SetQueryParams(map[string]string{
		"projectSlug":     request.ProjectSlug,
		"environmentSlug": request.EnvironmentSlug,
		"path":            request.SecretPath,
	})

	res, err := req.Get("/v1/dynamic-secrets/" + request.DynamicSecretName)

	if err != nil {
		return GetDynamicSecretByNameV1Response{}, errors.NewRequestError(callGetDynamicSecretByNameV1Operation, err)
	}

	if res.IsError() {
		return GetDynamicSecretByNameV1Response{}, errors.NewAPIErrorWithResponse(callGetDynamicSecretByNameV1Operation, res)
	}

	return getByNameResponse, nil
}
