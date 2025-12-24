package morpheus

import (
	"fmt"
)

var (
	// DatastoresPath is the API endpoint for datastores
	DatastoresPath = "/api/data-stores"
)

// ListDatastoresResult structure parses the list datastores response payload
type ListDatastoresResult struct {
	Datastores *[]Datastore `json:"datastores"`
	Meta       *MetaResult  `json:"meta"`
}

type GetDatastoreResult struct {
	Datastore *Datastore `json:"datastore"`
}

type CreateDatastoreResult struct {
	Success   bool              `json:"success"`
	Message   string            `json:"msg"`
	Errors    map[string]string `json:"errors"`
	Datastore *Datastore        `json:"datastore"`
}

type UpdateDatastoreResult struct {
	CreateDatastoreResult
}

type DeleteDatastoreResult struct {
	DeleteResult
}

// ListDatastores lists all datastores
func (client *Client) ListDatastores(req *Request) (*Response, error) {
	return client.Execute(&Request{
		Method:      "GET",
		Path:        DatastoresPath,
		QueryParams: req.QueryParams,
		Result:      &ListDatastoresResult{},
	})
}

// GetDatastore gets an datastore
func (client *Client) GetDatastore(id int64, req *Request) (*Response, error) {
	return client.Execute(&Request{
		Method:      "GET",
		Path:        fmt.Sprintf("%s/%d", DatastoresPath, id),
		QueryParams: req.QueryParams,
		Result:      &GetDatastoreResult{},
	})
}

// CreateDatastore creates a new datastore
func (client *Client) CreateDatastore(req *Request) (*Response, error) {
	return client.Execute(&Request{
		Method:      "POST",
		Path:        DatastoresPath,
		QueryParams: req.QueryParams,
		Body:        req.Body,
		Result:      &CreateDatastoreResult{},
	})
}

// UpdateDatastore updates an existing datastore
func (client *Client) UpdateDatastore(id int64, req *Request) (*Response, error) {
	return client.Execute(&Request{
		Method:      "PUT",
		Path:        fmt.Sprintf("%s/%d", DatastoresPath, id),
		QueryParams: req.QueryParams,
		Body:        req.Body,
		Result:      &UpdateDatastoreResult{},
	})
}

// DeleteDatastore deletes an existing datastore
func (client *Client) DeleteDatastore(id int64, req *Request) (*Response, error) {
	return client.Execute(&Request{
		Method:      "DELETE",
		Path:        fmt.Sprintf("%s/%d", DatastoresPath, id),
		QueryParams: req.QueryParams,
		Body:        req.Body,
		Result:      &DeleteDatastoreResult{},
	})
}

// FindDatastoreByName gets an existing datastore by name
func (client *Client) FindDatastoreByName(name string) (*Response, error) {
	// Find by name, then get by ID
	resp, err := client.ListDatastores(&Request{
		QueryParams: map[string]string{
			"name": name,
		},
	})
	if err != nil {
		return resp, err
	}
	listResult := resp.Result.(*ListDatastoresResult)
	datastoresCount := len(*listResult.Datastores)
	if datastoresCount != 1 {
		return resp, fmt.Errorf("found %d Datastores for %v", datastoresCount, name)
	}
	firstRecord := (*listResult.Datastores)[0]
	datastoreID := firstRecord.ID
	return client.GetDatastore(datastoreID, &Request{})
}
