package api

import (
	"github.com/go-resty/resty/v2"
	"github.com/infisical/go-sdk/packages/errors"
)

const callSignSshPublicKeyOperation = "CallSignSshPublicKeyV1"

func CallSignSshPublicKeyV1(httpClient *resty.Client, request SignSshPublicKeyV1Request) (SignSshPublicKeyV1Response, error) {
	signSshPublicKeyResponse := SignSshPublicKeyV1Response{}

	res, err := httpClient.R().
		SetResult(&signSshPublicKeyResponse).
		SetBody(request).
		Post("/v1/ssh/certificates/sign")

	if err != nil {
		return SignSshPublicKeyV1Response{}, errors.NewRequestError(callSignSshPublicKeyOperation, err)
	}

	if res.IsError() {
		return SignSshPublicKeyV1Response{}, errors.NewAPIErrorWithResponse(callSignSshPublicKeyOperation, res)
	}

	return signSshPublicKeyResponse, nil
}
