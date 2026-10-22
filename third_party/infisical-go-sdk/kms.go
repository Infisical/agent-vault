package infisical

import (
	"encoding/base64"

	api "github.com/infisical/go-sdk/packages/api/kms"
)

// Options
type KmsEncryptDataOptions = api.KmsEncryptDataV1Request
type KmsDecryptDataOptions = api.KmsDecryptDataV1Request

type KmsSignDataOptions = api.KmsSignDataV1Request
type KmsVerifyDataOptions = api.KmsVerifyDataV1Request

type KmsListSigningAlgorithmsOptions = api.KmsListSigningAlgorithmsV1Request
type KmsGetPublicKeyOptions = api.KmsGetPublicKeyV1Request

type KmsCreateKeyOptions = api.KmsCreateKeyV1Request
type KmsDeleteKeyOptions = api.KmsDeleteKeyV1Request

type KmsGetKeyByNameOptions = api.KmsGetKeyByNameV1Request

// Results
type KmsVerifyDataResult = api.KmsVerifyDataV1Response
type KmsSignDataResult = api.KmsSignDataV1Response

type KmsCreateKeyResult = api.KmsKey
type KmsDeleteKeyResult = api.KmsKey
type KmsGetKeyResult = api.KmsKey

type KmsKeysInterface interface {
	Create(options KmsCreateKeyOptions) (KmsCreateKeyResult, error)
	Delete(options KmsDeleteKeyOptions) (KmsDeleteKeyResult, error)
	GetByName(options KmsGetKeyByNameOptions) (KmsGetKeyResult, error)
}

type KmsSigningInterface interface {
	SignData(options KmsSignDataOptions) ([]byte, error)
	VerifyData(options KmsVerifyDataOptions) (KmsVerifyDataResult, error)
	ListSigningAlgorithms(options KmsListSigningAlgorithmsOptions) ([]string, error)
	GetPublicKey(options KmsGetPublicKeyOptions) (string, error)
}

type KmsInterface interface {
	EncryptData(options KmsEncryptDataOptions) (string, error)
	DecryptData(options KmsDecryptDataOptions) (string, error)

	Keys() KmsKeysInterface
	Signing() KmsSigningInterface
}

type Kms struct {
	client  *InfisicalClient
	keys    *KmsKeys
	signing *KmsSigning
}

type KmsKeys struct {
	client *InfisicalClient
}

type KmsSigning struct {
	client *InfisicalClient
}

func (k *KmsKeys) Create(options KmsCreateKeyOptions) (KmsCreateKeyResult, error) {
	res, err := api.CallKmsCreateKeyV1(k.client.httpClient, options)

	if err != nil {
		return KmsCreateKeyResult{}, err
	}

	return res.Key, nil
}

func (k *KmsKeys) Delete(options KmsDeleteKeyOptions) (KmsDeleteKeyResult, error) {
	res, err := api.CallKmsDeleteKeyV1(k.client.httpClient, options)

	if err != nil {
		return KmsDeleteKeyResult{}, err
	}

	return res.Key, nil
}

func (k *KmsKeys) GetByName(options KmsGetKeyByNameOptions) (KmsGetKeyResult, error) {
	res, err := api.CallKmsGetKeyByNameV1(k.client.httpClient, options)

	if err != nil {
		return KmsGetKeyResult{}, err
	}

	return res.Key, nil
}

func (k *KmsSigning) SignData(options KmsSignDataOptions) ([]byte, error) {
	res, err := api.CallKmsSignDataV1(k.client.httpClient, options)

	if err != nil {
		return nil, err
	}

	return base64.StdEncoding.DecodeString(res.Signature)
}

func (k *KmsSigning) VerifyData(options KmsVerifyDataOptions) (KmsVerifyDataResult, error) {
	res, err := api.CallKmsVerifyDataV1(k.client.httpClient, options)

	if err != nil {
		return KmsVerifyDataResult{}, err
	}

	return res, nil
}

func (k *KmsSigning) ListSigningAlgorithms(options KmsListSigningAlgorithmsOptions) ([]string, error) {
	res, err := api.CallKmsGetSigningAlgorithmsV1(k.client.httpClient, options)

	if err != nil {
		return []string{}, err
	}

	return res.SigningAlgorithms, nil
}

func (k *KmsSigning) GetPublicKey(options KmsGetPublicKeyOptions) (string, error) {
	res, err := api.CallKmsGetPublicKeyV1(k.client.httpClient, options)

	if err != nil {
		return "", err
	}

	return res.PublicKey, nil
}

func (f *Kms) EncryptData(options KmsEncryptDataOptions) (string, error) {
	options.Plaintext = base64.StdEncoding.EncodeToString([]byte(options.Plaintext))
	res, err := api.CallKmsEncryptDataV1(f.client.httpClient, options)

	if err != nil {
		return "", err
	}

	return res.Ciphertext, nil
}

func (f *Kms) DecryptData(options KmsDecryptDataOptions) (string, error) {
	res, err := api.CallKmsDecryptDataV1(f.client.httpClient, options)

	if err != nil {
		return "", err
	}

	decodedPlaintext, err := base64.StdEncoding.DecodeString(res.Plaintext)
	if err != nil {
		return "", err
	}

	return string(decodedPlaintext), nil
}

func (f *Kms) Keys() KmsKeysInterface {
	return &KmsKeys{client: f.client}
}

func (f *Kms) Signing() KmsSigningInterface {
	return &KmsSigning{client: f.client}
}

func NewKms(client *InfisicalClient) KmsInterface {
	return &Kms{
		client:  client,
		keys:    &KmsKeys{client: client},
		signing: &KmsSigning{client: client},
	}
}
