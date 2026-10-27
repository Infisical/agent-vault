package api

import (
	"github.com/go-resty/resty/v2"
	"github.com/infisical/go-sdk/packages/errors"
)

const callCreateFolderV1Operation = "CallCreateFolderV1"

func CallCreateFolderV1(httpClient *resty.Client, request CreateFolderV1Request) (CreateFolderV1Response, error) {

	createResponse := CreateFolderV1Response{}

	req := httpClient.R().
		SetResult(&createResponse).
		SetBody(request)

	res, err := req.Post("/v1/folders")

	if err != nil {
		return CreateFolderV1Response{}, errors.NewRequestError(callCreateFolderV1Operation, err)
	}

	if res.IsError() {
		return CreateFolderV1Response{}, errors.NewAPIErrorWithResponse(callCreateFolderV1Operation, res)
	}

	return createResponse, nil
}
