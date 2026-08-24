package limiter

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/eko/gocache/lib/v4/cache"
	"github.com/eko/gocache/lib/v4/store"
	redisStore "github.com/eko/gocache/store/redis/v4"
	"github.com/go-redis/redis/v8"
	"github.com/vmihailenco/msgpack"
)

type globalIPCache interface {
	Get(ctx context.Context, key interface{}, returnObj interface{}) (interface{}, error)
	Set(ctx context.Context, key, object interface{}, options ...store.Option) error
}

type layeredGlobalIPCache struct {
	localMu     sync.Mutex
	local       map[string]globalIPCacheEntry
	localExpiry time.Duration
	localWrites uint64
	remote      cache.SetterCacheInterface[any]
	redisClient *redis.Client
	closeOnce   sync.Once
	closeErr    error
}

type globalIPCacheEntry struct {
	value     []byte
	expiresAt time.Time
}

func newLayeredGlobalIPCache(config *GlobalDeviceLimitConfig) *layeredGlobalIPCache {
	expiry := time.Duration(config.Expiry) * time.Second
	redisClient := redis.NewClient(&redis.Options{
		Addr:     config.RedisAddr,
		Password: config.RedisPassword,
		DB:       config.RedisDB,
	})
	remoteStore := redisStore.NewRedis(redisClient, store.WithExpiration(expiry))
	return &layeredGlobalIPCache{
		local:       make(map[string]globalIPCacheEntry),
		localExpiry: expiry,
		remote:      cache.New[any](remoteStore),
		redisClient: redisClient,
	}
}

func (c *layeredGlobalIPCache) Get(ctx context.Context, key interface{}, returnObj interface{}) (interface{}, error) {
	keyString, ok := key.(string)
	if !ok {
		return nil, fmt.Errorf("global IP cache key has type %T, want string", key)
	}
	if value, found := c.getLocal(keyString); found {
		return unmarshalGlobalIPValue(value, returnObj)
	}
	if c.remote == nil {
		return nil, store.NotFoundWithCause(fmt.Errorf("global IP cache value not found"))
	}

	value, ttl, err := c.remote.GetWithTTL(ctx, keyString)
	if err != nil {
		return nil, err
	}
	data, err := globalIPValueBytes(value)
	if err != nil {
		return nil, err
	}
	c.setLocal(keyString, data, ttl)
	return unmarshalGlobalIPValue(data, returnObj)
}

func (c *layeredGlobalIPCache) Set(ctx context.Context, key, object interface{}, options ...store.Option) error {
	keyString, ok := key.(string)
	if !ok {
		return fmt.Errorf("global IP cache key has type %T, want string", key)
	}
	value, err := msgpack.Marshal(object)
	if err != nil {
		return fmt.Errorf("marshal global IP cache: %w", err)
	}
	expiry := c.localExpiry
	if applied := store.ApplyOptions(options...); applied.Expiration != 0 {
		expiry = applied.Expiration
	}
	c.setLocal(keyString, value, expiry)
	if c.remote == nil {
		return nil
	}
	if err := c.remote.Set(ctx, keyString, value, options...); err != nil {
		return fmt.Errorf("set remote global IP cache: %w", err)
	}
	return nil
}

func (c *layeredGlobalIPCache) getLocal(key string) ([]byte, bool) {
	c.localMu.Lock()
	defer c.localMu.Unlock()
	entry, found := c.local[key]
	if !found {
		return nil, false
	}
	if !entry.expiresAt.IsZero() && time.Now().After(entry.expiresAt) {
		delete(c.local, key)
		return nil, false
	}
	return entry.value, true
}

func (c *layeredGlobalIPCache) setLocal(key string, value []byte, expiry time.Duration) {
	entry := globalIPCacheEntry{value: value}
	if expiry > 0 {
		entry.expiresAt = time.Now().Add(expiry)
	}
	c.localMu.Lock()
	if c.local == nil {
		c.local = make(map[string]globalIPCacheEntry)
	}
	c.local[key] = entry
	c.localWrites++
	if c.localWrites%256 == 0 {
		now := time.Now()
		for cachedKey, cached := range c.local {
			if !cached.expiresAt.IsZero() && now.After(cached.expiresAt) {
				delete(c.local, cachedKey)
			}
		}
	}
	c.localMu.Unlock()
}

func unmarshalGlobalIPValue(value interface{}, returnObj interface{}) (interface{}, error) {
	data, err := globalIPValueBytes(value)
	if err != nil {
		return nil, err
	}
	if err := msgpack.Unmarshal(data, returnObj); err != nil {
		return nil, err
	}
	return returnObj, nil
}

func globalIPValueBytes(value interface{}) ([]byte, error) {
	switch typed := value.(type) {
	case []byte:
		return typed, nil
	case string:
		return []byte(typed), nil
	default:
		return nil, fmt.Errorf("unexpected global IP cache value type %T", value)
	}
}

func (c *layeredGlobalIPCache) Close() error {
	c.closeOnce.Do(func() {
		c.localMu.Lock()
		c.local = make(map[string]globalIPCacheEntry)
		c.localMu.Unlock()
		if c.redisClient != nil {
			c.closeErr = c.redisClient.Close()
		}
	})
	return c.closeErr
}

func closeGlobalIPCache(globalCache globalIPCache) {
	if closer, ok := globalCache.(interface{ Close() error }); ok {
		if err := closer.Close(); err != nil {
			newError("close global cache").Base(err).AtError().WriteToLog()
		}
	}
}
