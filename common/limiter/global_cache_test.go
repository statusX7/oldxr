package limiter

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/vmihailenco/msgpack"
)

func TestLayeredGlobalIPCacheRedisCompatibility(t *testing.T) {
	address := os.Getenv("XRAYR_TEST_REDIS_ADDR")
	if address == "" {
		t.Skip("XRAYR_TEST_REDIS_ADDR is not set")
	}

	ctx := context.Background()
	client := redis.NewClient(&redis.Options{Addr: address})
	defer client.Close()
	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatalf("ping Redis: %v", err)
	}

	key := fmt.Sprintf("oldxr-global-cache-test:%d:%d", os.Getpid(), time.Now().UnixNano())
	defer client.Del(ctx, key)
	legacyValue := map[string]int{"192.0.2.1": 17}
	legacyBytes, err := msgpack.Marshal(&legacyValue)
	if err != nil {
		t.Fatalf("marshal legacy value: %v", err)
	}
	if err := client.Set(ctx, key, legacyBytes, 5*time.Second).Err(); err != nil {
		t.Fatalf("seed legacy Redis value: %v", err)
	}

	globalCache := newLayeredGlobalIPCache(&GlobalDeviceLimitConfig{
		Enable:    true,
		RedisAddr: address,
		Timeout:   1,
		Expiry:    5,
	})
	defer globalCache.Close()
	result, err := globalCache.Get(ctx, key, new(map[string]int))
	if err != nil {
		t.Fatalf("read legacy Redis value: %v", err)
	}
	if got := *result.(*map[string]int); !reflect.DeepEqual(got, legacyValue) {
		t.Fatalf("legacy Redis value = %#v, want %#v", got, legacyValue)
	}

	updated := map[string]int{"192.0.2.1": 17, "198.51.100.2": 23}
	if err := globalCache.Set(ctx, key, &updated); err != nil {
		t.Fatalf("write current Redis value: %v", err)
	}
	storedBytes, err := client.Get(ctx, key).Bytes()
	if err != nil {
		t.Fatalf("read current Redis bytes: %v", err)
	}
	var stored map[string]int
	if err := msgpack.Unmarshal(storedBytes, &stored); err != nil {
		t.Fatalf("decode current Redis bytes with legacy msgpack format: %v", err)
	}
	if !reflect.DeepEqual(stored, updated) {
		t.Fatalf("current Redis value = %#v, want %#v", stored, updated)
	}
	if ttl, err := client.TTL(ctx, key).Result(); err != nil {
		t.Fatalf("read Redis TTL: %v", err)
	} else if ttl <= 0 || ttl > 5*time.Second {
		t.Fatalf("Redis TTL = %s, want (0s, 5s]", ttl)
	}
}
