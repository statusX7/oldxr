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

type atomicGlobalIPCache interface {
	ReserveIP(ctx context.Context, key, ip string, uid, limit int) (bool, error)
}

var reserveGlobalIPScript = redis.NewScript(`
local raw = redis.call('GET', KEYS[1])
local values = {}
if raw then
    values = cmsgpack.unpack(raw)
end

local ip = ARGV[1]
if values[ip] == nil then
    local count = 0
    for _ in pairs(values) do
        count = count + 1
    end
    local limit = tonumber(ARGV[3])
    if limit > 0 and count >= limit then
        return {0, raw or ''}
    end
    values[ip] = tonumber(ARGV[2])
    raw = cmsgpack.pack(values)
    redis.call('SET', KEYS[1], raw)
end

local expiry = tonumber(ARGV[4])
if expiry > 0 then
    redis.call('EXPIRE', KEYS[1], expiry)
end
if not raw then
    raw = cmsgpack.pack(values)
end
return {1, raw}
`)

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

// ReserveIP atomically admits an IP at the configured device boundary. Every
// Redis-backed decision executes on Redis so independent oldxr processes
// cannot accept different first IPs from stale process-local snapshots.
func (c *layeredGlobalIPCache) ReserveIP(ctx context.Context, key, ip string, uid, limit int) (bool, error) {
	if c.redisClient == nil {
		return c.reserveLocal(key, ip, uid, limit)
	}

	result, err := reserveGlobalIPScript.Run(
		ctx,
		c.redisClient,
		[]string{key},
		ip,
		uid,
		limit,
		int64(c.localExpiry/time.Second),
	).Result()
	if err != nil {
		return false, fmt.Errorf("reserve remote global IP: %w", err)
	}
	parts, ok := result.([]interface{})
	if !ok || len(parts) != 2 {
		return false, fmt.Errorf("reserve remote global IP returned %T, want two values", result)
	}
	status, ok := parts[0].(int64)
	if !ok {
		return false, fmt.Errorf("reserve remote global IP status has type %T", parts[0])
	}
	if status == 0 {
		c.deleteLocal(key)
		return false, nil
	}
	if status != 1 {
		return false, fmt.Errorf("reserve remote global IP returned status %d", status)
	}
	data, err := globalIPValueBytes(parts[1])
	if err != nil {
		return false, fmt.Errorf("decode reserved global IP value: %w", err)
	}
	c.setLocal(key, data, c.localExpiry)
	return true, nil
}

func (c *layeredGlobalIPCache) reserveLocal(key, ip string, uid, limit int) (bool, error) {
	c.localMu.Lock()
	defer c.localMu.Unlock()

	now := time.Now()
	entry, found := c.local[key]
	if found && !entry.expiresAt.IsZero() && now.After(entry.expiresAt) {
		delete(c.local, key)
		found = false
	}
	values := make(map[string]int)
	if found {
		if err := msgpack.Unmarshal(entry.value, &values); err != nil {
			return false, fmt.Errorf("unmarshal local global IP value: %w", err)
		}
	}
	if _, exists := values[ip]; !exists {
		if limit > 0 && len(values) >= limit {
			return false, nil
		}
		values[ip] = uid
	}
	encoded, err := msgpack.Marshal(&values)
	if err != nil {
		return false, fmt.Errorf("marshal local global IP value: %w", err)
	}
	entry = globalIPCacheEntry{value: encoded}
	if c.localExpiry > 0 {
		entry.expiresAt = now.Add(c.localExpiry)
	}
	if c.local == nil {
		c.local = make(map[string]globalIPCacheEntry)
	}
	c.local[key] = entry
	return true, nil
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

func (c *layeredGlobalIPCache) deleteLocal(key string) {
	c.localMu.Lock()
	delete(c.local, key)
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
