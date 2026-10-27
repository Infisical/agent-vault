package api

type KmsEncryptDataV1Request struct {
	KeyId     string
	Plaintext string `json:"plaintext"`
}

type KmsEncryptDataV1Response struct {
	Ciphertext string `json:"ciphertext"`
}

type KmsDecryptDataV1Request struct {
	KeyId      string
	Ciphertext string `json:"ciphertext"`
}

type KmsDecryptDataV1Response struct {
	Plaintext string `json:"plaintext"`
}

type KmsSignDataV1Request struct {
	KeyId            string
	Data             string `json:"data"`
	SigningAlgorithm string `json:"signingAlgorithm"`
	IsDigest         bool   `json:"isDigest"`
}

type KmsSignDataV1Response struct {
	Signature        string `json:"signature"`
	KeyId            string `json:"keyId"`
	SigningAlgorithm string `json:"signingAlgorithm"`
}

type KmsVerifyDataV1Request struct {
	KeyId            string
	Data             string `json:"data"` // Data must be base64 encoded
	Signature        string `json:"signature"`
	SigningAlgorithm string `json:"signingAlgorithm"`
	IsDigest         bool   `json:"isDigest"`
}

type KmsVerifyDataV1Response struct {
	SignatureValid   bool   `json:"signatureValid"`
	KeyId            string `json:"keyId"`
	SigningAlgorithm string `json:"signingAlgorithm"`
}

type KmsListSigningAlgorithmsV1Request struct {
	KeyId string
}

type KmsListSigningAlgorithmsV1Response struct {
	SigningAlgorithms []string `json:"signingAlgorithms"`
}

type KmsGetPublicKeyV1Request struct {
	KeyId string
}

type KmsGetPublicKeyV1Response struct {
	PublicKey string `json:"publicKey"`
}

type KmsCreateKeyV1Request struct {
	// KeyUsage is the usage of the key. Can be either sign-verify or encrypt-decrypt
	KeyUsage string `json:"keyUsage"`

	// Description is the description of the key.
	Description string `json:"description"`

	// Name is the name of the key.
	Name string `json:"name"`

	// EncryptionAlgorithm is the algorithm that will be used for the key itself.
	// `sign-verify algorithms`: `rsa-4096`, `ecc-nist-p256`
	// `encrypt-decrypt algorithms`: `aes-256-gcm`, `aes-128-gcm`
	EncryptionAlgorithm string `json:"encryptionAlgorithm"`

	// ProjectId is the project ID that the key will be created in.
	ProjectId string `json:"projectId"`
}

type KmsCreateKeyV1Response struct {
	Key KmsKey `json:"key"`
}

type KmsDeleteKeyV1Request struct {
	KeyId string
}

type KmsDeleteKeyV1Response struct {
	Key KmsKey `json:"key"`
}

type KmsGetKeyByNameV1Request struct {
	KeyName   string
	ProjectId string
}

type KmsGetKeyV1Response struct {
	Key KmsKey `json:"key"`
}

type KmsKey struct {
	KeyId               string `json:"id"`
	Description         string `json:"description"`
	IsDisabled          bool   `json:"isDisabled"`
	OrgId               string `json:"orgId"`
	Name                string `json:"name"`
	ProjectId           string `json:"projectId"`
	KeyUsage            string `json:"keyUsage"`
	Version             int    `json:"version"`
	EncryptionAlgorithm string `json:"encryptionAlgorithm"`
}
