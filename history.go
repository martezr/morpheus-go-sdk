package morpheus

import "time"

var (
	// HistoryPath is the API endpoint for history
	HistoryPath = "/api/processes"
)

// Process structures for use in request and response payloads
type Process struct {
	ID          int64  `json:"id"`
	AccountId   int64  `json:"accountId"`
	UniqueId    string `json:"uniqueId"`
	ProcessType struct {
		Code string `json:"code"`
		Name string `json:"name"`
	} `json:"processType"`
	DisplayName   string  `json:"displayName"`
	SubType       string  `json:"subType"`
	SubID         string  `json:"subId"`
	ZoneID        int     `json:"zoneId"`
	IntegrationID string  `json:"integrationId"`
	AppID         string  `json:"appId"`
	InstanceID    int64   `json:"instanceId"`
	ContainerID   int64   `json:"containerId"`
	ServerID      int64   `json:"serverId"`
	ContainerName string  `json:"containerName"`
	Status        string  `json:"status"`
	Reason        string  `json:"reason"`
	Percent       float32 `json:"percent"`
	StatusEta     int64   `json:"statusEta"`
	Message       string  `json:"message"`
	Output        string  `json:"output"`
	Error         string  `json:"error"`
	Duration      int64   `json:"duration"`
	CreatedBy     struct {
		Username    string `json:"username"`
		DisplayName string `json:"displayName"`
	} `json:"createdBy"`
	UpdatedBy struct {
		Username    string `json:"username"`
		DisplayName string `json:"displayName"`
	} `json:"updatedBy"`
	StartDate string  `json:"startDate"`
	EndDate   string  `json:"endDate"`
	Events    []Event `json:"events"`
}

type Event struct {
	ID          int    `json:"id"`
	ProcessID   int    `json:"processId"`
	AccountID   int    `json:"accountId"`
	UniqueID    string `json:"uniqueId"`
	ProcessType struct {
		Code string `json:"code"`
		Name string `json:"name"`
	} `json:"processType"`
	Description   string    `json:"description"`
	RefType       string    `json:"refType"`
	RefID         int64     `json:"refId"`
	SubType       string    `json:"subType"`
	SubID         string    `json:"subId"`
	ZoneID        int64     `json:"zoneId"`
	IntegrationID int64     `json:"integrationId"`
	InstanceID    int64     `json:"instanceId"`
	ContainerID   int64     `json:"containerId"`
	ServerID      int       `json:"serverId"`
	ContainerName string    `json:"containerName"`
	DisplayName   string    `json:"displayName"`
	Status        string    `json:"status"`
	Reason        string    `json:"reason"`
	Percent       float32   `json:"percent"`
	StatusEta     int64     `json:"statusEta"`
	Message       string    `json:"message"`
	Output        string    `json:"output"`
	Error         string    `json:"error"`
	StartDate     time.Time `json:"startDate"`
	EndDate       time.Time `json:"endDate"`
	Duration      int       `json:"duration"`
	DateCreated   time.Time `json:"dateCreated"`
	LastUpdated   time.Time `json:"lastUpdated"`
	CreatedBy     struct {
		Username    string `json:"username"`
		DisplayName string `json:"displayName"`
	} `json:"createdBy"`
	UpdatedBy struct {
		Username    string `json:"username"`
		DisplayName string `json:"displayName"`
	} `json:"updatedBy"`
}

// GetHistoryResult structure parses the list alerts response payload
type GetHistoryResult struct {
	Processes *[]Process  `json:"processes"`
	Meta      *MetaResult `json:"meta"`
}

// GetHistory get history
func (client *Client) GetHistory(req *Request) (*Response, error) {
	return client.Execute(&Request{
		Method:      "GET",
		Path:        HistoryPath,
		QueryParams: req.QueryParams,
		Result:      &GetHistoryResult{},
	})
}
