package models

import "time"

type Folder struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Version       int       `json:"version"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
	EnvironmentID string    `json:"envId"`
	ParentID      string    `json:"parentId"`
	IsReserved    bool      `json:"isReserved"`
}
