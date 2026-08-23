package fastengine

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/statusX7/oldxr/fastengine/control/internal/config"
)

const maxAdminResponse = 8 << 20

type VMessUser struct {
	UID uint64 `json:"uid"`
	ID  string `json:"id"`
}

type ShadowsocksUser struct {
	UID      uint64 `json:"uid"`
	Password string `json:"password"`
}

type Traffic struct {
	UID      uint64 `json:"uid"`
	Upload   uint64 `json:"upload"`
	Download uint64 `json:"download"`
}

type Client struct {
	SocketPath string
	Timeout    time.Duration
}

func New(socketPath string) *Client {
	return &Client{SocketPath: socketPath, Timeout: 5 * time.Second}
}

func (c *Client) call(ctx context.Context, request, result any) error {
	if c.SocketPath == "" {
		return errors.New("FastEngine admin socket path is empty")
	}
	dialer := net.Dialer{Timeout: c.Timeout}
	connection, err := dialer.DialContext(ctx, "unix", c.SocketPath)
	if err != nil {
		return err
	}
	defer connection.Close()
	deadline := time.Now().Add(c.Timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return err
	}
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		return err
	}
	var response struct {
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
		Error  string          `json:"error"`
	}
	reader := bufio.NewReader(io.LimitReader(connection, maxAdminResponse+1))
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return err
	}
	if len(line) > maxAdminResponse {
		return errors.New("FastEngine admin response exceeds limit")
	}
	if err := json.Unmarshal(line, &response); err != nil {
		return fmt.Errorf("decode FastEngine admin response: %w", err)
	}
	if !response.OK {
		if response.Error == "" {
			response.Error = "unknown FastEngine admin error"
		}
		return errors.New(response.Error)
	}
	if result != nil && len(response.Result) != 0 && string(response.Result) != "null" {
		if err := json.Unmarshal(response.Result, result); err != nil {
			return fmt.Errorf("decode FastEngine admin result: %w", err)
		}
	}
	return nil
}

func (c *Client) Ping(ctx context.Context) error {
	var result struct {
		Pong bool `json:"pong"`
	}
	if err := c.call(ctx, map[string]any{"operation": "ping"}, &result); err != nil {
		return err
	}
	if !result.Pong {
		return errors.New("FastEngine ping response has no pong")
	}
	return nil
}

func (c *Client) ReplaceRouting(ctx context.Context, routing config.RoutingPlan) error {
	return c.call(ctx, map[string]any{"operation": "replace_routing", "routing": routing}, nil)
}

func (c *Client) ReplaceVMessUsers(ctx context.Context, site int, users []VMessUser) error {
	return c.call(ctx, map[string]any{"operation": "replace_vmess_users", "site": site, "users": users}, nil)
}

func (c *Client) ReplaceShadowsocksUsers(ctx context.Context, site int, users []ShadowsocksUser) error {
	return c.call(ctx, map[string]any{"operation": "replace_ss_users", "site": site, "users": users}, nil)
}

func (c *Client) TakeVMessTraffic(ctx context.Context, site int) ([]Traffic, error) {
	var traffic []Traffic
	err := c.call(ctx, map[string]any{"operation": "take_vmess_traffic", "site": site}, &traffic)
	return traffic, err
}

func (c *Client) TakeShadowsocksTraffic(ctx context.Context, site int) ([]Traffic, error) {
	var traffic []Traffic
	err := c.call(ctx, map[string]any{"operation": "take_ss_traffic", "site": site}, &traffic)
	return traffic, err
}

func (c *Client) RestoreVMessTraffic(ctx context.Context, site int, traffic []Traffic) error {
	return c.call(ctx, map[string]any{"operation": "restore_vmess_traffic", "site": site, "traffic": traffic}, nil)
}

func (c *Client) RestoreShadowsocksTraffic(ctx context.Context, site int, traffic []Traffic) error {
	return c.call(ctx, map[string]any{"operation": "restore_ss_traffic", "site": site, "traffic": traffic}, nil)
}

func (c *Client) UpdateVMessPolicy(ctx context.Context, site int, speedBytesPerSecond uint64, deviceLimit int, rules []string) error {
	return c.call(ctx, map[string]any{
		"operation":              "update_vmess_policy",
		"site":                   site,
		"speed_bytes_per_second": speedBytesPerSecond,
		"device_limit":           deviceLimit,
		"rules":                  rules,
	}, nil)
}

func (c *Client) UpdateShadowsocksPolicy(ctx context.Context, site int, speedBytesPerSecond uint64, deviceLimit int, rules []string) error {
	return c.call(ctx, map[string]any{
		"operation":              "update_ss_policy",
		"site":                   site,
		"speed_bytes_per_second": speedBytesPerSecond,
		"device_limit":           deviceLimit,
		"rules":                  rules,
	}, nil)
}

func (c *Client) Status(ctx context.Context, protocol string, result any) error {
	operation := "vmess_status"
	if protocol == "shadowsocks" {
		operation = "ss_status"
	}
	return c.call(ctx, map[string]any{"operation": operation}, result)
}
