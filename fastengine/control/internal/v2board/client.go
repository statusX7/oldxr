package v2board

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxResponseBytes = 64 << 20

type Protocol string

const (
	VMess       Protocol = "vmess"
	Shadowsocks Protocol = "shadowsocks"
)

type NodeInfo struct {
	Port       int
	Network    string
	Security   string
	HeaderType string
	Rules      []string
}

type User struct {
	UID      uint64
	UUID     string
	AlterID  uint16
	Email    string
	Port     int
	Cipher   string
	Password string
}

type Traffic struct {
	UID      uint64 `json:"user_id"`
	Upload   uint64 `json:"u"`
	Download uint64 `json:"d"`
}

type Client struct {
	host     string
	key      string
	nodeID   int
	protocol Protocol
	http     *http.Client

	mu       sync.Mutex
	etag     string
	hasUsers bool
}

func ProtocolFromNodeType(nodeType string) (Protocol, error) {
	switch {
	case strings.EqualFold(nodeType, "V2ray"):
		return VMess, nil
	case strings.EqualFold(nodeType, "Shadowsocks"):
		return Shadowsocks, nil
	default:
		return "", fmt.Errorf("unsupported V2Board node type %q", nodeType)
	}
}

func New(host, key string, nodeID, timeoutSeconds int, protocol Protocol) *Client {
	if timeoutSeconds <= 0 {
		timeoutSeconds = 5
	}
	return &Client{
		host:     strings.TrimRight(host, "/"),
		key:      key,
		nodeID:   nodeID,
		protocol: protocol,
		http:     &http.Client{Timeout: time.Duration(timeoutSeconds) * time.Second},
	}
}

func (c *Client) endpoint(path string, localPort bool) (string, error) {
	u, err := url.Parse(c.host + path)
	if err != nil {
		return "", err
	}
	query := u.Query()
	query.Set("node_id", strconv.Itoa(c.nodeID))
	query.Set("token", c.key)
	if localPort {
		query.Set("local_port", "1")
	}
	u.RawQuery = query.Encode()
	return u.String(), nil
}

func (c *Client) do(request *http.Request) (*http.Response, error) {
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt != 0 && request.GetBody != nil {
			body, err := request.GetBody()
			if err != nil {
				return nil, err
			}
			request.Body = body
		}
		response, err := c.http.Do(request)
		if err == nil {
			return response, nil
		}
		last = err
		if request.Context().Err() != nil {
			break
		}
	}
	return nil, last
}

func checkStatus(response *http.Response, operation string) error {
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	return fmt.Errorf("%s: status=%d body=%q", operation, response.StatusCode, body)
}

func (c *Client) FetchNode(ctx context.Context) (NodeInfo, error) {
	if c.protocol != VMess {
		return NodeInfo{}, errors.New("Shadowsocks node metadata is carried by the legacy user response")
	}
	endpoint, err := c.endpoint("/api/v1/server/Deepbwork/config", true)
	if err != nil {
		return NodeInfo{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return NodeInfo{}, err
	}
	response, err := c.do(request)
	if err != nil {
		return NodeInfo{}, err
	}
	defer response.Body.Close()
	if err := checkStatus(response, "GET VMess node config"); err != nil {
		return NodeInfo{}, err
	}
	var envelope struct {
		Inbound  json.RawMessage   `json:"inbound"`
		Inbounds []json.RawMessage `json:"inbounds"`
		Routing  struct {
			Rules []struct {
				Domain []string `json:"domain"`
			} `json:"rules"`
		} `json:"routing"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, maxResponseBytes)).Decode(&envelope); err != nil {
		return NodeInfo{}, fmt.Errorf("decode VMess node config: %w", err)
	}
	inbound := envelope.Inbound
	if len(inbound) == 0 && len(envelope.Inbounds) != 0 {
		inbound = envelope.Inbounds[0]
	}
	if len(inbound) == 0 {
		return NodeInfo{}, errors.New("VMess node config has no inbound or inbounds entry")
	}
	var decoded struct {
		Port           json.RawMessage `json:"port"`
		StreamSettings struct {
			Network  string `json:"network"`
			Security string `json:"security"`
			TCP      struct {
				Header struct {
					Type string `json:"type"`
				} `json:"header"`
			} `json:"tcpSettings"`
		} `json:"streamSettings"`
	}
	if err := json.Unmarshal(inbound, &decoded); err != nil {
		return NodeInfo{}, fmt.Errorf("decode VMess inbound: %w", err)
	}
	port, err := jsonInteger(decoded.Port)
	if err != nil || port <= 0 || port > 65535 {
		return NodeInfo{}, fmt.Errorf("invalid VMess listen port: %s", decoded.Port)
	}
	var rules []string
	if len(envelope.Routing.Rules) > 1 {
		rules = append(rules, envelope.Routing.Rules[1].Domain...)
	}
	return NodeInfo{
		Port:       port,
		Network:    decoded.StreamSettings.Network,
		Security:   decoded.StreamSettings.Security,
		HeaderType: decoded.StreamSettings.TCP.Header.Type,
		Rules:      rules,
	}, nil
}

func jsonInteger(raw json.RawMessage) (int, error) {
	if len(raw) == 0 {
		return 0, errors.New("missing integer")
	}
	var number int
	if err := json.Unmarshal(raw, &number); err == nil {
		return number, nil
	}
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return 0, err
	}
	return strconv.Atoi(text)
}

func (c *Client) FetchUsers(ctx context.Context) ([]User, bool, error) {
	path := "/api/v1/server/Deepbwork/user"
	if c.protocol == Shadowsocks {
		path = "/api/v1/server/ShadowsocksTidalab/user"
	}
	endpoint, err := c.endpoint(path, false)
	if err != nil {
		return nil, false, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, false, err
	}
	c.mu.Lock()
	etag := c.etag
	hasUsers := c.hasUsers
	c.mu.Unlock()
	if etag != "" {
		request.Header.Set("If-None-Match", etag)
	}
	response, err := c.do(request)
	if err != nil {
		return nil, false, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotModified {
		if !hasUsers {
			return nil, false, errors.New("V2Board returned 304 before a full user response")
		}
		return nil, true, nil
	}
	if err := checkStatus(response, "GET users"); err != nil {
		return nil, false, err
	}
	users, err := decodeUsers(io.LimitReader(response.Body, maxResponseBytes), c.protocol)
	if err != nil {
		return nil, false, err
	}
	c.mu.Lock()
	c.etag = response.Header.Get("ETag")
	c.hasUsers = true
	c.mu.Unlock()
	return users, false, nil
}

func decodeUsers(reader io.Reader, protocol Protocol) ([]User, error) {
	if protocol == VMess {
		var response struct {
			Data []struct {
				UID   uint64 `json:"id"`
				VMess struct {
					UUID    string `json:"uuid"`
					Email   string `json:"email"`
					AlterID uint16 `json:"alter_id"`
				} `json:"v2ray_user"`
			} `json:"data"`
		}
		if err := json.NewDecoder(reader).Decode(&response); err != nil {
			return nil, fmt.Errorf("decode VMess users: %w", err)
		}
		users := make([]User, 0, len(response.Data))
		for _, item := range response.Data {
			users = append(users, User{UID: item.UID, UUID: item.VMess.UUID, AlterID: item.VMess.AlterID, Email: item.VMess.Email})
		}
		return users, nil
	}
	var response struct {
		Data []struct {
			UID      uint64 `json:"id"`
			Port     int    `json:"port"`
			Cipher   string `json:"cipher"`
			Password string `json:"secret"`
		} `json:"data"`
	}
	if err := json.NewDecoder(reader).Decode(&response); err != nil {
		return nil, fmt.Errorf("decode Shadowsocks users: %w", err)
	}
	users := make([]User, 0, len(response.Data))
	for _, item := range response.Data {
		users = append(users, User{UID: item.UID, Port: item.Port, Cipher: item.Cipher, Password: item.Password})
	}
	return users, nil
}

func (c *Client) SubmitTraffic(ctx context.Context, traffic []Traffic) error {
	if len(traffic) == 0 {
		return nil
	}
	path := "/api/v1/server/Deepbwork/submit"
	if c.protocol == Shadowsocks {
		path = "/api/v1/server/ShadowsocksTidalab/submit"
	}
	endpoint, err := c.endpoint(path, false)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(traffic)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	return checkStatus(response, "POST traffic")
}
