package infisical

import (
	api "github.com/infisical/go-sdk/packages/api/folders"
	"github.com/infisical/go-sdk/packages/models"
)

type ListFoldersOptions = api.ListFoldersV1Request
type UpdateFolderOptions = api.UpdateFolderV1Request
type CreateFolderOptions = api.CreateFolderV1Request
type DeleteFolderOptions = api.DeleteFolderV1Request

type FoldersInterface interface {
	List(options ListFoldersOptions) ([]models.Folder, error)
	Update(options UpdateFolderOptions) (models.Folder, error)
	Create(options CreateFolderOptions) (models.Folder, error)
	Delete(options DeleteFolderOptions) (models.Folder, error)
}

type Folders struct {
	client *InfisicalClient
}

func (f *Folders) List(options ListFoldersOptions) ([]models.Folder, error) {
	res, err := api.CallListFoldersV1(f.client.httpClient, options)

	if err != nil {
		return nil, err
	}

	return res.Folders, nil
}

func (f *Folders) Update(options UpdateFolderOptions) (models.Folder, error) {
	res, err := api.CallUpdateFolderV1(f.client.httpClient, options)

	if err != nil {
		return models.Folder{}, err
	}

	return res.Folder, nil
}

func (f *Folders) Create(options CreateFolderOptions) (models.Folder, error) {
	res, err := api.CallCreateFolderV1(f.client.httpClient, options)

	if err != nil {
		return models.Folder{}, err
	}

	return res.Folder, nil
}

func (f *Folders) Delete(options DeleteFolderOptions) (models.Folder, error) {
	res, err := api.CallDeleteFolderV1(f.client.httpClient, options)

	if err != nil {
		return models.Folder{}, err
	}

	return res.Folder, nil
}

func NewFolders(client *InfisicalClient) FoldersInterface {
	return &Folders{client: client}
}
