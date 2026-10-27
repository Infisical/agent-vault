package api

import (
	"github.com/go-resty/resty/v2"
	"github.com/infisical/go-sdk/packages/errors"
)

const callListDynamicSecretsV1Operation = "CallListDynamicSecretSecretsV1"

func CallListDynamicSecretsV1(httpClient *resty.Client, request ListDynamicSecretsV1Request) (ListDynamicSecretsV1Response, error) {

	listDynamicSecretResponse := ListDynamicSecretsV1Response{}

	req := httpClient.R().
		SetResult(&listDynamicSecretResponse).
		SetQueryParams(map[string]string{
			"projectSlug":     request.ProjectSlug,
			"environmentSlug": request.EnvironmentSlug,
			"path":            request.SecretPath,
		})

	res, err := req.Get("/v1/dynamic-secrets")

	if err != nil {
		return ListDynamicSecretsV1Response{}, errors.NewRequestError(callListDynamicSecretsV1Operation, err)
	}

	if res.IsError() {
		return ListDynamicSecretsV1Response{}, errors.NewAPIErrorWithResponse(callListDynamicSecretsV1Operation, res)
	}

	return listDynamicSecretResponse, nil
}
