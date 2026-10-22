package api

import (
	"fmt"

	"github.com/go-resty/resty/v2"
	"github.com/infisical/go-sdk/packages/errors"
)

const callDeleteFolderV1Operation = "CallDeleteFolderV1"

func CallDeleteFolderV1(httpClient *resty.Client, request DeleteFolderV1Request) (DeleteFolderV1Response, error) {

	deleteResponse := DeleteFolderV1Response{}

	// Either folderID or folderName must be provided
	var folderIdOrName string
	if request.FolderID != "" {
		folderIdOrName = request.FolderID
	} else if request.FolderName != "" {
		folderIdOrName = request.FolderName
	} else {
		return DeleteFolderV1Response{}, fmt.Errorf("CallDeleteFolderV1: Either folderID or folderName must be provided")
	}

	req := httpClient.R().
		SetResult(&deleteResponse).
		SetBody(request)

	res, err := req.Delete(fmt.Sprintf("/v1/folders/%s", folderIdOrName))

	if err != nil {
		return DeleteFolderV1Response{}, errors.NewRequestError(callDeleteFolderV1Operation, err)
	}

	if res.IsError() {
		return DeleteFolderV1Response{}, errors.NewAPIErrorWithResponse(callDeleteFolderV1Operation, res)
	}

	return deleteResponse, nil
}
