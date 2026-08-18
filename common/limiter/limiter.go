// Package limiter is to control the links that go into the dispatcher
package limiter

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/eko/gocache/lib/v4/store"
	"golang.org/x/time/rate"

	"github.com/XrayR-project/XrayR/api"
)

type UserInfo struct {
	UID         int
	SpeedLimit  uint64
	DeviceLimit int
}

type InboundInfo struct {
	Tag            string
	NodeSpeedLimit uint64
	UserInfo       *sync.Map // Key: Email value: UserInfo
	BucketHub      *sync.Map // key: Email, value: *rate.Limiter
	UserOnlineIP   *sync.Map // Key: Email, value: {Key: IP, value: UID}
	localIPLocks   [deviceLockShards]sync.Mutex
	GlobalLimit    struct {
		config         *GlobalDeviceLimitConfig
		globalOnlineIP globalIPCache
		ipLocks        [deviceLockShards]sync.Mutex
	}
}

type Limiter struct {
	InboundInfo *sync.Map // Key: Tag, Value: *InboundInfo
}

func New() *Limiter {
	return &Limiter{
		InboundInfo: new(sync.Map),
	}
}

func (l *Limiter) AddInboundLimiter(tag string, nodeSpeedLimit uint64, userList *[]api.UserInfo, globalLimit *GlobalDeviceLimitConfig) error {
	inboundInfo := &InboundInfo{
		Tag:            tag,
		NodeSpeedLimit: nodeSpeedLimit,
		BucketHub:      new(sync.Map),
		UserOnlineIP:   new(sync.Map),
	}

	if globalLimit != nil && globalLimit.Enable {
		inboundInfo.GlobalLimit.config = globalLimit
		inboundInfo.GlobalLimit.globalOnlineIP = newLayeredGlobalIPCache(globalLimit)
	}

	userMap := new(sync.Map)
	for _, u := range *userList {
		userMap.Store(formatUserKey(tag, u.Email, u.UID), UserInfo{
			UID:         u.UID,
			SpeedLimit:  u.SpeedLimit,
			DeviceLimit: u.DeviceLimit,
		})
	}
	inboundInfo.UserInfo = userMap
	if old, loaded := l.InboundInfo.Swap(tag, inboundInfo); loaded {
		closeGlobalIPCache(old.(*InboundInfo).GlobalLimit.globalOnlineIP)
	}
	return nil
}

func (l *Limiter) UpdateInboundLimiter(tag string, updatedUserList *[]api.UserInfo) error {
	if value, ok := l.InboundInfo.Load(tag); ok {
		inboundInfo := value.(*InboundInfo)
		// Update User info
		for _, u := range *updatedUserList {
			email := formatUserKey(tag, u.Email, u.UID)
			localLock := deviceLock(&inboundInfo.localIPLocks, email)
			localLock.Lock()
			inboundInfo.UserInfo.Store(email, UserInfo{
				UID:         u.UID,
				SpeedLimit:  u.SpeedLimit,
				DeviceLimit: u.DeviceLimit,
			})
			// Update old limiter bucket
			limit := determineRate(inboundInfo.NodeSpeedLimit, u.SpeedLimit)
			if limit > 0 {
				if bucket, ok := inboundInfo.BucketHub.Load(email); ok {
					limiter := bucket.(*rate.Limiter)
					limiter.SetLimit(rate.Limit(limit))
					limiter.SetBurst(int(limit))
				}
			} else {
				inboundInfo.BucketHub.Delete(email)
			}
			localLock.Unlock()
		}
	} else {
		return fmt.Errorf("no such inbound in limiter: %s", tag)
	}
	return nil
}

func (l *Limiter) DeleteInboundLimiterUsers(tag string, deletedUserList *[]api.UserInfo) error {
	value, ok := l.InboundInfo.Load(tag)
	if !ok {
		return fmt.Errorf("no such inbound in limiter: %s", tag)
	}
	inboundInfo := value.(*InboundInfo)
	for _, user := range *deletedUserList {
		email := formatUserKey(tag, user.Email, user.UID)
		localLock := deviceLock(&inboundInfo.localIPLocks, email)
		localLock.Lock()
		inboundInfo.UserInfo.Delete(email)
		inboundInfo.BucketHub.Delete(email)
		inboundInfo.UserOnlineIP.Delete(email)
		localLock.Unlock()
	}
	return nil
}

func (l *Limiter) DeleteInboundLimiter(tag string) error {
	if value, loaded := l.InboundInfo.LoadAndDelete(tag); loaded {
		closeGlobalIPCache(value.(*InboundInfo).GlobalLimit.globalOnlineIP)
	}
	return nil
}

func (l *Limiter) GetOnlineDevice(tag string) (*[]api.OnlineUser, error) {
	var onlineUser []api.OnlineUser

	if value, ok := l.InboundInfo.Load(tag); ok {
		inboundInfo := value.(*InboundInfo)
		// Clear Speed Limiter bucket for users who are not online
		inboundInfo.BucketHub.Range(func(key, value interface{}) bool {
			email := key.(string)
			if _, exists := inboundInfo.UserOnlineIP.Load(email); !exists {
				inboundInfo.BucketHub.Delete(email)
			}
			return true
		})
		inboundInfo.UserOnlineIP.Range(func(key, value interface{}) bool {
			email := key.(string)
			localLock := deviceLock(&inboundInfo.localIPLocks, email)
			localLock.Lock()
			ipMap := value.(*sync.Map)
			ipMap.Range(func(key, value interface{}) bool {
				uid := value.(int)
				ip := key.(string)
				onlineUser = append(onlineUser, api.OnlineUser{UID: uid, IP: ip})
				return true
			})
			inboundInfo.UserOnlineIP.Delete(email) // Reset online device
			localLock.Unlock()
			return true
		})
	} else {
		return nil, fmt.Errorf("no such inbound in limiter: %s", tag)
	}

	return &onlineUser, nil
}

func (l *Limiter) GetUserBucket(tag string, email string, ip string) (limiter *rate.Limiter, SpeedLimit bool, Reject bool) {
	if value, ok := l.InboundInfo.Load(tag); ok {
		var (
			userLimit        uint64 = 0
			deviceLimit, uid int
		)

		inboundInfo := value.(*InboundInfo)
		nodeLimit := inboundInfo.NodeSpeedLimit

		// Local device limit. Serialize one user's first-IP decisions so a burst
		// cannot temporarily insert every IP and then reject all contenders.
		localLock := deviceLock(&inboundInfo.localIPLocks, email)
		localLock.Lock()
		userValue, userExists := inboundInfo.UserInfo.Load(email)
		if !userExists {
			localLock.Unlock()
			return nil, false, false
		}
		u := userValue.(UserInfo)
		uid = u.UID
		userLimit = u.SpeedLimit
		deviceLimit = u.DeviceLimit
		value, exists := inboundInfo.UserOnlineIP.Load(email)
		var ipMap *sync.Map
		if exists {
			ipMap = value.(*sync.Map)
		} else {
			ipMap = new(sync.Map)
			inboundInfo.UserOnlineIP.Store(email, ipMap)
		}
		if _, exists := ipMap.Load(ip); !exists {
			counter := 0
			if deviceLimit > 0 {
				ipMap.Range(func(key, value interface{}) bool {
					counter++
					return counter < deviceLimit
				})
			}
			if deviceLimit > 0 && counter >= deviceLimit {
				localLock.Unlock()
				return nil, false, true
			}
			ipMap.Store(ip, uid)
		}

		// Speed limit
		limit := determineRate(nodeLimit, userLimit) // Determine the speed limit rate
		var bucket *rate.Limiter
		var speedLimited bool
		if limit > 0 {
			if value, exists := inboundInfo.BucketHub.Load(email); exists {
				bucket = value.(*rate.Limiter)
			} else {
				bucket = rate.NewLimiter(rate.Limit(limit), int(limit)) // Byte/s
				inboundInfo.BucketHub.Store(email, bucket)
			}
			speedLimited = true
		}
		localLock.Unlock()

		// GlobalLimit
		if inboundInfo.GlobalLimit.config != nil && inboundInfo.GlobalLimit.config.Enable {
			if reject := globalLimit(inboundInfo, email, uid, ip, deviceLimit); reject {
				return nil, false, true
			}
		}

		return bucket, speedLimited, false
	} else {
		newError("Get Inbound Limiter information failed").AtDebug().WriteToLog()
		return nil, false, false
	}
}

// Global device limit
func globalLimit(inboundInfo *InboundInfo, email string, uid int, ip string, deviceLimit int) bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(inboundInfo.GlobalLimit.config.Timeout)*time.Second)
	defer cancel()

	// reformat email for unique key
	uniqueKey := strings.Replace(email, inboundInfo.Tag, strconv.Itoa(deviceLimit), 1)
	globalLock := deviceLock(&inboundInfo.GlobalLimit.ipLocks, uniqueKey)
	globalLock.Lock()
	defer globalLock.Unlock()

	v, err := inboundInfo.GlobalLimit.globalOnlineIP.Get(ctx, uniqueKey, new(map[string]int))
	if err != nil {
		if _, ok := err.(*store.NotFound); ok {
			// If the email is a new device
			if err := pushIP(ctx, inboundInfo, uniqueKey, &map[string]int{ip: uid}); err != nil {
				newError("cache service").Base(err).AtError().WriteToLog()
			}
		} else {
			newError("cache service").Base(err).AtError().WriteToLog()
		}
		return false
	}

	ipMap := v.(*map[string]int)
	if _, ok := (*ipMap)[ip]; ok {
		return false
	}
	// Reject a new IP when the existing set is already at the limit.
	if deviceLimit > 0 && len(*ipMap) >= deviceLimit {
		return true
	}

	updated := make(map[string]int, len(*ipMap)+1)
	for cachedIP, cachedUID := range *ipMap {
		updated[cachedIP] = cachedUID
	}
	updated[ip] = uid
	if err := pushIP(ctx, inboundInfo, uniqueKey, &updated); err != nil {
		newError("cache service").Base(err).AtError().WriteToLog()
	}

	return false
}

// push the ip to cache
func pushIP(ctx context.Context, inboundInfo *InboundInfo, uniqueKey string, ipMap *map[string]int) error {
	return inboundInfo.GlobalLimit.globalOnlineIP.Set(ctx, uniqueKey, ipMap)
}

const deviceLockShards = 64

func deviceLock(locks *[deviceLockShards]sync.Mutex, key string) *sync.Mutex {
	const fnvOffset32 = uint32(2166136261)
	const fnvPrime32 = uint32(16777619)
	hash := fnvOffset32
	for i := 0; i < len(key); i++ {
		hash ^= uint32(key[i])
		hash *= fnvPrime32
	}
	return &locks[hash%deviceLockShards]
}

func formatUserKey(tag string, email string, uid int) string {
	var uidBuffer [20]byte
	uidBytes := strconv.AppendInt(uidBuffer[:0], int64(uid), 10)
	var key strings.Builder
	key.Grow(len(tag) + len(email) + len(uidBytes) + 2)
	key.WriteString(tag)
	key.WriteByte('|')
	key.WriteString(email)
	key.WriteByte('|')
	key.Write(uidBytes)
	return key.String()
}

// determineRate returns the minimum non-zero rate
func determineRate(nodeLimit, userLimit uint64) (limit uint64) {
	if nodeLimit == 0 || userLimit == 0 {
		if nodeLimit > userLimit {
			return nodeLimit
		} else if nodeLimit < userLimit {
			return userLimit
		} else {
			return 0
		}
	} else {
		if nodeLimit > userLimit {
			return userLimit
		} else if nodeLimit < userLimit {
			return nodeLimit
		} else {
			return nodeLimit
		}
	}
}
