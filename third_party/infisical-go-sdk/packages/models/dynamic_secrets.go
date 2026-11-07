package models

import "time"

type DynamicSecret struct {
	Id            string    `json:"id"`
	Name          string    `json:"name"`
	Type          string    `json:"type"`
	Version       int       `json:"number"`
	DefaultTTL    string    `json:"defaultTTL"`
	MaxTTL        string    `json:"maxTTL"`
	FolderID      string    `json:"folderId"`
	Status        string    `json:"status"`
	StatusDetails string    `json:"statusDetails"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

type DynamicSecretLease struct {
	Id               string    `json:"id"`
	Type             string    `json:"type"`
	Version          int       `json:"number"`
	ExternalEntityId string    `json:"externalEntityId"`
	ExpireAt         time.Time `json:"expireAt"`
	Status           string    `json:"status"`
	DynamicSecretId  string    `json:"dynamicSecretId"`
	StatusDetails    string    `json:"statusDetails"`
	CreatedAt        time.Time `json:"createdAt"`
	UpdatedAt        time.Time `json:"updatedAt"`
}

type DynamicSecretLeaseWithDynamicSecret struct {
	Id               string        `json:"id"`
	Type             string        `json:"type"`
	Version          int           `json:"number"`
	ExternalEntityId string        `json:"externalEntityId"`
	ExpireAt         time.Time     `json:"expireAt"`
	Status           string        `json:"status"`
	DynamicSecretId  string        `json:"dynamicSecretId"`
	StatusDetails    string        `json:"statusDetails"`
	CreatedAt        time.Time     `json:"createdAt"`
	UpdatedAt        time.Time     `json:"updatedAt"`
	DynamicSecret    DynamicSecret `json:"dynamicSecret"`
}
