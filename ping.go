package morpheus

import (
	_ "fmt"
)

var (
	PingPath = "/api/ping"
)

type PingResult struct {
	Success      bool   `json:"success"`
	Message      string `json:"msg"`
	BuildVersion string `json:"buildVersion"`
}

func (client *Client) Ping(req *Request) (*Response, error) {
	return client.Execute(&Request{
		Method:      "GET",
		Path:        (PingPath + "/ping"),
		QueryParams: req.QueryParams,
		Result:      &PingResult{},
	})
}
