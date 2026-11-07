package api

import (
	"github.com/go-resty/resty/v2"
	"github.com/infisical/go-sdk/packages/errors"
)

const callListFoldersV1Operation = "CallListFoldersV1"

func CallListFoldersV1(httpClient *resty.Client, request ListFoldersV1Request) (ListFoldersV1Response, error) {

	secretsResponse := ListFoldersV1Response{}

	queryParams := map[string]string{
		"workspaceId": request.ProjectID,
		"environment": request.Environment,
	}

	if request.Path != "" {
		queryParams["path"] = request.Path
	}

	res, err := httpClient.R().
		SetResult(&secretsResponse).
		SetQueryParams(queryParams).Get("/v1/folders")

	if err != nil {
		return ListFoldersV1Response{}, errors.NewRequestError(callListFoldersV1Operation, err)
	}

	if res.IsError() {
		return ListFoldersV1Response{}, errors.NewAPIErrorWithResponse(callListFoldersV1Operation, res)
	}

	return secretsResponse, nil
}
