package panel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

type User struct {
	UID      int    `json:"id"`
	Port     int    `json:"port"`
	Cipher   string `json:"cipher"`
	Password string `json:"secret"`
}

type Traffic struct {
	UID      int   `json:"user_id"`
	Upload   int64 `json:"u"`
	Download int64 `json:"d"`
}

type Client struct {
	host   string
	key    string
	nodeID int
	http   *http.Client

	mu   sync.Mutex
	etag string
}

func New(host, key string, nodeID, timeoutSeconds int) *Client {
	return &Client{
		host:   host,
		key:    key,
		nodeID: nodeID,
		http:   &http.Client{Timeout: time.Duration(timeoutSeconds) * time.Second},
	}
}

func (c *Client) endpoint(path string) (string, error) {
	u, err := url.Parse(c.host + path)
	if err != nil {
		return "", err
	}
	query := u.Query()
	query.Set("node_id", strconv.Itoa(c.nodeID))
	query.Set("token", c.key)
	u.RawQuery = query.Encode()
	return u.String(), nil
}

func (c *Client) FetchUsers(ctx context.Context) ([]User, bool, error) {
	endpoint, err := c.endpoint("/api/v1/server/ShadowsocksTidalab/user")
	if err != nil {
		return nil, false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, false, err
	}
	c.mu.Lock()
	etag := c.etag
	c.mu.Unlock()
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotModified {
		return nil, true, nil
	}
	if res.StatusCode >= http.StatusBadRequest {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return nil, false, fmt.Errorf("GET users: status=%d body=%q", res.StatusCode, body)
	}
	var response struct {
		Data []User `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 64<<20)).Decode(&response); err != nil {
		return nil, false, err
	}
	if len(response.Data) == 0 {
		return nil, false, fmt.Errorf("V2Board returned an empty Shadowsocks user list")
	}
	c.mu.Lock()
	c.etag = res.Header.Get("ETag")
	c.mu.Unlock()
	return response.Data, false, nil
}

func (c *Client) SubmitTraffic(ctx context.Context, traffic []Traffic) error {
	if len(traffic) == 0 {
		return nil
	}
	payload, err := json.Marshal(traffic)
	if err != nil {
		return err
	}
	endpoint, err := c.endpoint("/api/v1/server/ShadowsocksTidalab/submit")
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= http.StatusBadRequest {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return fmt.Errorf("POST traffic: status=%d body=%q", res.StatusCode, body)
	}
	return nil
}
