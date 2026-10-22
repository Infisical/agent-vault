package api

import (
	"encoding/json"
	"fmt"

	"github.com/go-resty/resty/v2"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/infisical/go-sdk/packages/errors"
	"github.com/infisical/go-sdk/packages/util"
)

const callListSecretsV3RawOperation = "CallListSecretsV3Raw"

func CallListSecretsV3(cache *expirable.LRU[string, interface{}], httpClient *resty.Client, request ListSecretsV3RawRequest) (ListSecretsV3RawResponse, error) {
	var cacheKey string

	if cache != nil {
		reqBytes, err := json.Marshal(request)
		if err != nil {
			return ListSecretsV3RawResponse{}, err
		}
		cacheKey = util.ComputeCacheKeyFromBytes(reqBytes, callListSecretsV3RawOperation)
		if cached, found := cache.Get(cacheKey); found {
			if response, ok := cached.(ListSecretsV3RawResponse); ok {
				return response, nil
			}
			cache.Remove(cacheKey)
		}
	}

	secretsResponse := ListSecretsV3RawResponse{}

	if request.SecretPath == "" {
		request.SecretPath = "/"
	}

	req := httpClient.R().
		SetResult(&secretsResponse).
		SetQueryParams(map[string]string{
			"workspaceId":            request.ProjectID,
			"workspaceSlug":          request.ProjectSlug,
			"environment":            request.Environment,
			"secretPath":             request.SecretPath,
			"expandSecretReferences": fmt.Sprintf("%t", request.ExpandSecretReferences),
			"include_imports":        fmt.Sprintf("%t", request.IncludeImports),
			"recursive":              fmt.Sprintf("%t", request.Recursive),
		})

	if request.IfNoneMatch != "" {
		req.SetHeader("If-None-Match", request.IfNoneMatch)
	}

	res, err := req.Get("/v3/secrets/raw")

	if err != nil {
		return ListSecretsV3RawResponse{}, errors.NewRequestError(callListSecretsV3RawOperation, err)
	}

	if res.StatusCode() == 304 {
		return ListSecretsV3RawResponse{}, errors.NewNotModifiedError(callListSecretsV3RawOperation)
	}

	if res.IsError() {
		return ListSecretsV3RawResponse{}, errors.NewAPIErrorWithResponse(callListSecretsV3RawOperation, res)
	}

	secretsResponse.ETag = res.Header().Get("ETag")

	if cache != nil {
		cache.Add(cacheKey, secretsResponse)
	}

	return secretsResponse, nil
}
