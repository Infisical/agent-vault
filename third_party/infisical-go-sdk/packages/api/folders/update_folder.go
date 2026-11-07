package api

import (
	"fmt"

	"github.com/go-resty/resty/v2"
	"github.com/infisical/go-sdk/packages/errors"
)

const callUpdateFolderV1Operation = "CallUpdateFolderV1"

func CallUpdateFolderV1(httpClient *resty.Client, request UpdateFolderV1Request) (UpdateFolderV1Response, error) {

	updateResponse := UpdateFolderV1Response{}

	req := httpClient.R().
		SetResult(&updateResponse).
		SetBody(request)

	res, err := req.Patch(fmt.Sprintf("/v1/folders/%s", request.FolderID))

	if err != nil {
		return UpdateFolderV1Response{}, errors.NewRequestError(callUpdateFolderV1Operation, err)
	}

	if res.IsError() {
		return UpdateFolderV1Response{}, errors.NewAPIErrorWithResponse(callUpdateFolderV1Operation, res)
	}

	return updateResponse, nil
}
