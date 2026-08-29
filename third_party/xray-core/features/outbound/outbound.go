package outbound

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features"
	"github.com/xtls/xray-core/transport"
)

// Handler is the interface for handlers that process outbound connections.
//
// xray:api:stable
type Handler interface {
	common.Runnable
	Tag() string
	Dispatch(ctx context.Context, link *transport.Link)
}

// DirectHandler is an optional extension for handlers that can transfer
// ownership of a directly dialed connection to an inbound protocol handler.
// supported is false when mux or the configured outbound cannot use this path.
type DirectHandler interface {
	OpenDirect(ctx context.Context, destination net.Destination) (link *transport.DirectLink, supported bool, err error)
}

type HandlerSelector interface {
	Select([]string) []string
}

// Manager is a feature that manages outbound.Handlers.
//
// xray:api:stable
type Manager interface {
	features.Feature
	// GetHandler returns an outbound.Handler for the given tag.
	GetHandler(tag string) Handler
	// GetDefaultHandler returns the default outbound.Handler. It is usually the first outbound.Handler specified in the configuration.
	GetDefaultHandler() Handler
	// AddHandler adds a handler into this outbound.Manager.
	AddHandler(ctx context.Context, handler Handler) error

	// RemoveHandler removes a handler from outbound.Manager.
	RemoveHandler(ctx context.Context, tag string) error
}

// ManagerType returns the type of Manager interface. Can be used to implement common.HasType.
//
// xray:api:stable
func ManagerType() interface{} {
	return (*Manager)(nil)
}
