package morpheus

import "time"

var (
	// LogsPath is the API endpoint for logs
	LogsPath = "/api/logs"
)

// GetLogsResult structure parses the list alerts response payload
type GetLogsResult struct {
	Sort struct {
		TS string `json:"ts"`
	}
	Offset     int64             `json:"offset"`
	Start      time.Time         `json:"start"`
	End        time.Time         `json:"end"`
	Data       []LogData         `json:"data"`
	Max        int64             `json:"max"`
	GrandTotal int64             `json:"grandTotal"`
	Total      int64             `json:"total"`
	Success    bool              `json:"success"`
	Count      int64             `json:"count"`
	Meta       *MetaResult       `json:"meta"`
	Message    string            `json:"msg"`
	Errors     map[string]string `json:"errors"`
}

type LogData struct {
	TypeCode          string `json:"typeCode"`
	Message           string `json:"message"`
	Level             string `json:"level"`
	TS                string `json:"ts"`
	SourceType        string `json:"sourceType"`
	Title             string `json:"title"`
	LogSignature      string `json:"logSignature"`
	ObjectId          string `json:"objectId"`
	Seq               int64  `json:"seq"`
	Id                string `json:"_id"`
	SignatureVerified bool   `json:"signatureVerified"`
}

// GetHistory get history
func (client *Client) GetLogs(req *Request) (*Response, error) {
	return client.Execute(&Request{
		Method:      "GET",
		Path:        LogsPath,
		QueryParams: req.QueryParams,
		Result:      &GetLogsResult{},
	})
}
