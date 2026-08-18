package controller

import (
	"context"
	"fmt"
	"log"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"

	"github.com/XrayR-project/XrayR/api"
	"github.com/XrayR-project/XrayR/app/mydispatcher"
	"github.com/XrayR-project/XrayR/common/mylego"
	"github.com/XrayR-project/XrayR/common/serverstatus"
)

type LimitInfo struct {
	end               int64
	currentSpeedLimit int
	originSpeedLimit  uint64
}

type Controller struct {
	server       *core.Instance
	config       *Config
	stateMu      sync.RWMutex
	clientInfo   api.ClientInfo
	apiClient    api.API
	nodeInfo     *api.NodeInfo
	Tag          string
	userList     *[]api.UserInfo
	runtimeMu    sync.Mutex
	lifecycleMu  sync.Mutex
	taskContext  context.Context
	cancelTasks  context.CancelFunc
	taskWG       sync.WaitGroup
	tasksRunning bool
	tasks        []periodicTask
	limitedUsers map[api.UserInfo]LimitInfo
	warnedUsers  map[api.UserInfo]int
	panelType    string
	ibm          inbound.Manager
	obm          outbound.Manager
	stm          stats.Manager
	dispatcher   *mydispatcher.DefaultDispatcher
	startAt      time.Time
}

type periodicTask struct {
	tag      string
	interval time.Duration
	execute  func() error
}

type controllerSnapshot struct {
	clientInfo api.ClientInfo
	nodeInfo   *api.NodeInfo
	tag        string
	userList   *[]api.UserInfo
}

// New return a Controller service with default parameters.
func New(server *core.Instance, api api.API, config *Config, panelType string) *Controller {
	controller := &Controller{
		server:     server,
		config:     config,
		apiClient:  api,
		panelType:  panelType,
		ibm:        server.GetFeature(inbound.ManagerType()).(inbound.Manager),
		obm:        server.GetFeature(outbound.ManagerType()).(outbound.Manager),
		stm:        server.GetFeature(stats.ManagerType()).(stats.Manager),
		dispatcher: server.GetFeature(routing.DispatcherType()).(*mydispatcher.DefaultDispatcher),
		startAt:    time.Now(),
	}

	return controller
}

// Start implement the Start() function of the service interface
func (c *Controller) Start() error {
	clientInfo := c.apiClient.Describe()
	// First fetch Node Info
	newNodeInfo, err := c.apiClient.GetNodeInfo()
	if err != nil {
		return err
	}
	newTag := c.buildNodeTagFor(newNodeInfo)

	// Add new tag
	err = c.addNewTag(newNodeInfo, newTag)
	if err != nil {
		return err
	}
	// Update user
	userInfo, err := c.apiClient.GetUserList()
	if err != nil {
		return err
	}

	err = c.addNewUser(userInfo, newNodeInfo, newTag)
	if err != nil {
		return err
	}
	c.publishState(controllerSnapshot{
		clientInfo: clientInfo,
		nodeInfo:   newNodeInfo,
		tag:        newTag,
		userList:   userInfo,
	})

	// Add Limiter
	if err := c.AddInboundLimiter(newTag, newNodeInfo.SpeedLimit, userInfo, c.config.GlobalDeviceLimitConfig); err != nil {
		log.Print(err)
	}

	// Add Rule Manager
	if !c.config.DisableGetRule {
		if ruleList, err := c.apiClient.GetNodeRule(); err != nil {
			log.Printf("Get rule list filed: %s", err)
		} else if len(*ruleList) > 0 {
			if err := c.UpdateRule(newTag, *ruleList); err != nil {
				log.Print(err)
			}
		}
	}

	// Init AutoSpeedLimitConfig
	if c.config.AutoSpeedLimitConfig == nil {
		c.config.AutoSpeedLimitConfig = &AutoSpeedLimitConfig{0, 0, 0, 0}
	}
	if c.config.AutoSpeedLimitConfig.Limit > 0 {
		c.limitedUsers = make(map[api.UserInfo]LimitInfo)
		c.warnedUsers = make(map[api.UserInfo]int)
	}

	// Add periodic tasks
	c.tasks = []periodicTask{
		periodicTask{
			tag:      "node monitor",
			interval: time.Duration(c.config.UpdatePeriodic) * time.Second,
			execute:  c.nodeInfoMonitor,
		},
		periodicTask{
			tag:      "user monitor",
			interval: time.Duration(c.config.UpdatePeriodic) * time.Second,
			execute:  c.userInfoMonitor,
		},
	}

	// Check cert service in need
	if newNodeInfo.EnableTLS {
		c.tasks = append(c.tasks, periodicTask{
			tag:      "cert monitor",
			interval: time.Duration(c.config.UpdatePeriodic) * time.Second * 60,
			execute:  c.certMonitor,
		})
	}

	return c.startPeriodicTasks()
}

// Close implement the Close() function of the service interface
func (c *Controller) Close() error {
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	if !c.tasksRunning {
		return nil
	}
	c.cancelTasks()
	c.taskWG.Wait()
	c.tasksRunning = false
	c.taskContext = nil
	c.cancelTasks = nil

	return nil
}

func (c *Controller) startPeriodicTasks() error {
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	if c.tasksRunning {
		return nil
	}

	c.taskContext, c.cancelTasks = context.WithCancel(context.Background())
	c.tasksRunning = true
	c.taskWG.Add(len(c.tasks))
	for _, periodic := range c.tasks {
		log.Printf("%s Start %s periodic task", c.logPrefix(), periodic.tag)
		go c.runPeriodicTask(c.taskContext, periodic)
	}
	return nil
}

func (c *Controller) runPeriodicTask(ctx context.Context, periodic periodicTask) {
	defer c.taskWG.Done()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if err := periodic.execute(); err != nil {
			log.Printf("%s %s periodic task stopped: %s", c.logPrefix(), periodic.tag, err)
			return
		}

		timer := time.NewTimer(periodic.interval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-timer.C:
		}
	}
}

func (c *Controller) snapshot() controllerSnapshot {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return controllerSnapshot{
		clientInfo: c.clientInfo,
		nodeInfo:   c.nodeInfo,
		tag:        c.Tag,
		userList:   c.userList,
	}
}

func (c *Controller) publishState(state controllerSnapshot) {
	c.stateMu.Lock()
	c.clientInfo = state.clientInfo
	c.nodeInfo = state.nodeInfo
	c.Tag = state.tag
	c.userList = state.userList
	c.stateMu.Unlock()
}

func (c *Controller) nodeInfoMonitor() (err error) {
	// delay to start
	if time.Since(c.startAt) < time.Duration(c.config.UpdatePeriodic)*time.Second {
		return nil
	}

	// First fetch Node Info
	newNodeInfo, err := c.apiClient.GetNodeInfo()
	if err != nil {
		log.Print(err)
		return nil
	}

	oldState := c.snapshot()
	if oldState.nodeInfo == nil || oldState.userList == nil {
		return fmt.Errorf("controller state is not initialized")
	}

	// Update User
	var usersChanged = true
	newUserInfo, err := c.apiClient.GetUserList()
	if err != nil {
		if err.Error() == "users no change" {
			usersChanged = false
			newUserInfo = oldState.userList
		} else {
			log.Print(err)
			return nil
		}
	}

	var ruleList *[]api.DetectRule
	if !c.config.DisableGetRule {
		ruleList, err = c.apiClient.GetNodeRule()
		if err != nil {
			log.Printf("Get rule list filed: %s", err)
			ruleList = nil
		}
	}

	// Runtime mutations from the node monitor are serialized with traffic,
	// limiter and rule snapshots from the user monitor. Panel HTTP is complete
	// before this lock is acquired.
	c.runtimeMu.Lock()
	defer c.runtimeMu.Unlock()

	oldState = c.snapshot()
	if oldState.nodeInfo == nil || oldState.userList == nil {
		return fmt.Errorf("controller state is not initialized")
	}
	if !usersChanged {
		newUserInfo = oldState.userList
	}

	nodeInfoChanged := false
	activeTag := oldState.tag
	// If nodeInfo changed
	if !reflect.DeepEqual(oldState.nodeInfo, newNodeInfo) {
		// Remove old tag
		oldTag := oldState.tag
		err := c.removeOldTag(oldTag)
		if err != nil {
			log.Print(err)
			return nil
		}
		if oldState.nodeInfo.NodeType == "Shadowsocks-Plugin" {
			err = c.removeOldTag(fmt.Sprintf("dokodemo-door_%s+1", oldTag))
		}
		if err != nil {
			log.Print(err)
			return nil
		}
		// Add new tag
		activeTag = c.buildNodeTagFor(newNodeInfo)
		err = c.addNewTag(newNodeInfo, activeTag)
		if err != nil {
			log.Print(err)
			return nil
		}
		nodeInfoChanged = true
		c.publishState(controllerSnapshot{
			clientInfo: oldState.clientInfo,
			nodeInfo:   newNodeInfo,
			tag:        activeTag,
			userList:   oldState.userList,
		})
		// Remove Old limiter
		if err = c.DeleteInboundLimiter(oldTag); err != nil {
			log.Print(err)
			return nil
		}
	}

	// Check Rule
	if ruleList != nil && len(*ruleList) > 0 {
		if err := c.UpdateRule(activeTag, *ruleList); err != nil {
			log.Print(err)
		}
	}

	if nodeInfoChanged {
		err = c.addNewUser(newUserInfo, newNodeInfo, activeTag)
		if err != nil {
			log.Print(err)
			return nil
		}

		// Add Limiter
		if err := c.AddInboundLimiter(activeTag, newNodeInfo.SpeedLimit, newUserInfo, c.config.GlobalDeviceLimitConfig); err != nil {
			log.Print(err)
			return nil
		}

	} else {
		var deleted, added, limitUpdated []api.UserInfo
		if usersChanged {
			deleted, added, limitUpdated = compareUserList(oldState.userList, newUserInfo)
			if len(deleted) > 0 {
				deletedEmail := make([]string, len(deleted))
				for i, u := range deleted {
					deletedEmail[i] = formatUserTag(activeTag, &u)
				}
				err := c.removeUsers(deletedEmail, activeTag)
				if err != nil {
					log.Print(err)
				}
			}
			if len(added) > 0 {
				err = c.addNewUser(&added, oldState.nodeInfo, activeTag)
				if err != nil {
					log.Print(err)
				}
			}
			if len(added) > 0 || len(limitUpdated) > 0 {
				limiterUpdates := make([]api.UserInfo, 0, len(added)+len(limitUpdated))
				limiterUpdates = append(limiterUpdates, added...)
				limiterUpdates = append(limiterUpdates, limitUpdated...)
				if err := c.UpdateInboundLimiter(activeTag, &limiterUpdates); err != nil {
					log.Print(err)
				}
			}
		}
		log.Printf("%s %d user deleted, %d user added, %d user limits updated", logPrefixFor(oldState.clientInfo, oldState.nodeInfo), len(deleted), len(added), len(limitUpdated))
	}
	c.publishState(controllerSnapshot{
		clientInfo: oldState.clientInfo,
		nodeInfo:   newNodeInfo,
		tag:        activeTag,
		userList:   newUserInfo,
	})
	return nil
}

func (c *Controller) removeOldTag(oldTag string) (err error) {
	err = c.removeInbound(oldTag)
	if err != nil {
		return err
	}
	err = c.removeOutbound(oldTag)
	if err != nil {
		return err
	}
	return nil
}

func (c *Controller) addNewTag(newNodeInfo *api.NodeInfo, tag string) (err error) {
	if newNodeInfo.NodeType != "Shadowsocks-Plugin" {
		inboundConfig, err := InboundBuilder(c.config, newNodeInfo, tag)
		if err != nil {
			return err
		}
		err = c.addInbound(inboundConfig)
		if err != nil {

			return err
		}
		outBoundConfig, err := OutboundBuilder(c.config, newNodeInfo, tag)
		if err != nil {

			return err
		}
		err = c.addOutbound(outBoundConfig)
		if err != nil {

			return err
		}

	} else {
		return c.addInboundForSSPlugin(*newNodeInfo, tag)
	}
	return nil
}

func (c *Controller) addInboundForSSPlugin(newNodeInfo api.NodeInfo, tag string) (err error) {
	// Shadowsocks-Plugin require a separate inbound for other TransportProtocol likes: ws, grpc
	fakeNodeInfo := newNodeInfo
	fakeNodeInfo.TransportProtocol = "tcp"
	fakeNodeInfo.EnableTLS = false
	// Add a regular Shadowsocks inbound and outbound
	inboundConfig, err := InboundBuilder(c.config, &fakeNodeInfo, tag)
	if err != nil {
		return err
	}
	err = c.addInbound(inboundConfig)
	if err != nil {

		return err
	}
	outBoundConfig, err := OutboundBuilder(c.config, &fakeNodeInfo, tag)
	if err != nil {

		return err
	}
	err = c.addOutbound(outBoundConfig)
	if err != nil {

		return err
	}
	// Add an inbound for upper streaming protocol
	fakeNodeInfo = newNodeInfo
	fakeNodeInfo.Port++
	fakeNodeInfo.NodeType = "dokodemo-door"
	dokodemoTag := fmt.Sprintf("dokodemo-door_%s+1", tag)
	inboundConfig, err = InboundBuilder(c.config, &fakeNodeInfo, dokodemoTag)
	if err != nil {
		return err
	}
	err = c.addInbound(inboundConfig)
	if err != nil {

		return err
	}
	outBoundConfig, err = OutboundBuilder(c.config, &fakeNodeInfo, dokodemoTag)
	if err != nil {

		return err
	}
	err = c.addOutbound(outBoundConfig)
	if err != nil {

		return err
	}
	return nil
}

func (c *Controller) addNewUser(userInfo *[]api.UserInfo, nodeInfo *api.NodeInfo, tag string) (err error) {
	users := make([]*protocol.User, 0)
	switch nodeInfo.NodeType {
	case "V2ray":
		if nodeInfo.EnableVless {
			users = c.buildVlessUser(userInfo, tag)
		} else {
			var alterID uint16 = 0
			if (c.panelType == "V2board" || c.panelType == "V2RaySocks") && len(*userInfo) > 0 {
				// use latest userInfo
				alterID = (*userInfo)[0].AlterID
			} else {
				alterID = nodeInfo.AlterID
			}
			users = c.buildVmessUser(userInfo, alterID, tag)
		}
	case "Trojan":
		users = c.buildTrojanUser(userInfo, tag)
	case "Shadowsocks":
		users = c.buildSSUser(userInfo, nodeInfo.CypherMethod, tag)
	case "Shadowsocks-Plugin":
		users = c.buildSSPluginUser(userInfo, tag)
	default:
		return fmt.Errorf("unsupported node type: %s", nodeInfo.NodeType)
	}

	err = c.addUsers(users, tag)
	if err != nil {
		return err
	}
	log.Printf("[%s] Added %d new users", tag, len(*userInfo))
	return nil
}

func sameRuntimeUser(old, new api.UserInfo) bool {
	return old.UID == new.UID &&
		old.Email == new.Email &&
		old.Passwd == new.Passwd &&
		old.Port == new.Port &&
		old.Method == new.Method &&
		old.Protocol == new.Protocol &&
		old.ProtocolParam == new.ProtocolParam &&
		old.Obfs == new.Obfs &&
		old.ObfsParam == new.ObfsParam &&
		old.UUID == new.UUID &&
		old.AlterID == new.AlterID
}

func compareUserList(old, new *[]api.UserInfo) (deleted, added, limitUpdated []api.UserInfo) {
	oldIndex := make(map[int]int, len(*old))
	newUIDs := make(map[int]struct{}, len(*new))

	for i, u := range *old {
		oldIndex[u.UID] = i
	}

	for _, u := range *new {
		newUIDs[u.UID] = struct{}{}

		oldPosition, exists := oldIndex[u.UID]
		if !exists {
			added = append(added, u)
			continue
		}
		oldUser := (*old)[oldPosition]
		if !sameRuntimeUser(oldUser, u) {
			deleted = append(deleted, oldUser)
			added = append(added, u)
			continue
		}
		if oldUser.SpeedLimit != u.SpeedLimit || oldUser.DeviceLimit != u.DeviceLimit {
			limitUpdated = append(limitUpdated, u)
		}
	}

	for _, u := range *old {
		if _, exists := newUIDs[u.UID]; !exists {
			deleted = append(deleted, u)
		}
	}

	return deleted, added, limitUpdated
}

type statCounterVisitor interface {
	VisitCounters(func(string, stats.Counter) bool)
}

type trafficBucket struct {
	uid      int
	email    string
	upload   int64
	download int64
}

func parseTrafficUser(tag string, fullEmail string) (email string, uid int, ok bool) {
	prefix := tag + "|"
	if !strings.HasPrefix(fullEmail, prefix) {
		return "", 0, false
	}

	rest := strings.TrimPrefix(fullEmail, prefix)
	idx := strings.LastIndex(rest, "|")
	if idx <= 0 || idx >= len(rest)-1 {
		return "", 0, false
	}

	uid64, err := strconv.ParseInt(rest[idx+1:], 10, 64)
	if err != nil {
		return "", 0, false
	}

	return rest[:idx], int(uid64), true
}

func (c *Controller) collectTrafficByCounterVisit(tag string) (userTraffic []api.UserTraffic, deltas []trafficCounterDelta, ok bool) {
	visitor, ok := c.stm.(statCounterVisitor)
	if !ok {
		return nil, nil, false
	}

	buckets := make(map[string]*trafficBucket)

	visitor.VisitCounters(func(name string, counter stats.Counter) bool {
		parts := strings.Split(name, ">>>")
		if len(parts) != 4 {
			return true
		}

		if parts[0] != "user" || parts[2] != "traffic" {
			return true
		}

		email, uid, parsed := parseTrafficUser(tag, parts[1])
		if !parsed {
			return true
		}
		if parts[3] != "uplink" && parts[3] != "downlink" {
			return true
		}

		delta, hasTraffic := drainTrafficCounter(counter)
		if !hasTraffic {
			return true
		}
		deltas = append(deltas, delta)

		b := buckets[parts[1]]
		if b == nil {
			b = &trafficBucket{
				uid:   uid,
				email: email,
			}
			buckets[parts[1]] = b
		}

		switch parts[3] {
		case "uplink":
			b.upload = delta.value
		case "downlink":
			b.download = delta.value
		}

		return true
	})

	userTraffic = make([]api.UserTraffic, 0, len(buckets))

	for _, b := range buckets {
		if b.upload <= 0 && b.download <= 0 {
			continue
		}

		userTraffic = append(userTraffic, api.UserTraffic{
			UID:      b.uid,
			Email:    b.email,
			Upload:   b.upload,
			Download: b.download,
		})
	}

	return userTraffic, deltas, true
}

func limitUser(c *Controller, tag string, user api.UserInfo, silentUsers *[]api.UserInfo) {
	c.limitedUsers[user] = LimitInfo{
		end:               time.Now().Unix() + int64(c.config.AutoSpeedLimitConfig.LimitDuration*60),
		currentSpeedLimit: c.config.AutoSpeedLimitConfig.LimitSpeed,
		originSpeedLimit:  user.SpeedLimit,
	}
	log.Printf("Limit User: %s Speed: %d End: %s", formatUserTag(tag, &user), c.config.AutoSpeedLimitConfig.LimitSpeed, time.Unix(c.limitedUsers[user].end, 0).Format("01-02 15:04:05"))
	user.SpeedLimit = uint64((c.config.AutoSpeedLimitConfig.LimitSpeed * 1000000) / 8)
	*silentUsers = append(*silentUsers, user)
}

func (c *Controller) userInfoMonitor() (err error) {
	// delay to start
	if time.Since(c.startAt) < time.Duration(c.config.UpdatePeriodic)*time.Second {
		return nil
	}

	// Get server status
	CPU, Mem, Disk, Uptime, err := serverstatus.GetSystemInfo()
	if err != nil {
		log.Print(err)
	}
	err = c.apiClient.ReportNodeStatus(
		&api.NodeStatus{
			CPU:    CPU,
			Mem:    Mem,
			Disk:   Disk,
			Uptime: Uptime,
		})
	if err != nil {
		log.Print(err)
	}

	// Keep runtime snapshots consistent with node reloads. Network reporting is
	// performed after this lock is released.
	c.runtimeMu.Lock()
	runtimeUnlocked := false
	defer func() {
		if !runtimeUnlocked {
			c.runtimeMu.Unlock()
		}
	}()
	state := c.snapshot()
	if state.nodeInfo == nil || state.userList == nil {
		return fmt.Errorf("controller state is not initialized")
	}
	prefix := logPrefixFor(state.clientInfo, state.nodeInfo)
	// Unlock users
	if c.config.AutoSpeedLimitConfig.Limit > 0 && len(c.limitedUsers) > 0 {
		log.Printf("%s Limited users:", prefix)
		toReleaseUsers := make([]api.UserInfo, 0)
		for user, limitInfo := range c.limitedUsers {
			if time.Now().Unix() > limitInfo.end {
				user.SpeedLimit = limitInfo.originSpeedLimit
				toReleaseUsers = append(toReleaseUsers, user)
				log.Printf("User: %s Speed: %d End: nil (Unlimit)", formatUserTag(state.tag, &user), user.SpeedLimit)
				delete(c.limitedUsers, user)
			} else {
				log.Printf("User: %s Speed: %d End: %s", formatUserTag(state.tag, &user), limitInfo.currentSpeedLimit, time.Unix(c.limitedUsers[user].end, 0).Format("01-02 15:04:05"))
			}
		}
		if len(toReleaseUsers) > 0 {
			if err := c.UpdateInboundLimiter(state.tag, &toReleaseUsers); err != nil {
				log.Print(err)
			}
		}
	}

	// Get User traffic
	var userTraffic []api.UserTraffic
	var trafficDeltas []trafficCounterDelta

	AutoSpeedLimit := int64(c.config.AutoSpeedLimitConfig.Limit)

	if AutoSpeedLimit <= 0 {
		var ok bool
		userTraffic, trafficDeltas, ok = c.collectTrafficByCounterVisit(state.tag)
		if !ok {
			for _, user := range *state.userList {
				up, down, deltas := c.drainTraffic(formatUserTag(state.tag, &user))
				if up > 0 || down > 0 {
					userTraffic = append(userTraffic, api.UserTraffic{
						UID:      user.UID,
						Email:    user.Email,
						Upload:   up,
						Download: down,
					})

					trafficDeltas = append(trafficDeltas, deltas...)
				}
			}
		}
	} else {
		UpdatePeriodic := int64(c.config.UpdatePeriodic)
		limitedUsers := make([]api.UserInfo, 0)

		for _, user := range *state.userList {
			up, down, deltas := c.drainTraffic(formatUserTag(state.tag, &user))
			if up > 0 || down > 0 {
				// Over speed users
				if down > AutoSpeedLimit*1000000*UpdatePeriodic/8 || up > AutoSpeedLimit*1000000*UpdatePeriodic/8 {
					if _, ok := c.limitedUsers[user]; !ok {
						if c.config.AutoSpeedLimitConfig.WarnTimes == 0 {
							limitUser(c, state.tag, user, &limitedUsers)
						} else {
							c.warnedUsers[user] += 1
							if c.warnedUsers[user] > c.config.AutoSpeedLimitConfig.WarnTimes {
								limitUser(c, state.tag, user, &limitedUsers)
								delete(c.warnedUsers, user)
							}
						}
					}
				} else {
					delete(c.warnedUsers, user)
				}

				userTraffic = append(userTraffic, api.UserTraffic{
					UID:      user.UID,
					Email:    user.Email,
					Upload:   up,
					Download: down,
				})

				trafficDeltas = append(trafficDeltas, deltas...)
			} else {
				delete(c.warnedUsers, user)
			}
		}

		if len(limitedUsers) > 0 {
			if err := c.UpdateInboundLimiter(state.tag, &limitedUsers); err != nil {
				log.Print(err)
			}
		}
	}

	onlineDevice, onlineErr := c.GetOnlineDevice(state.tag)
	detectResult, detectErr := c.GetDetectResult(state.tag)
	c.runtimeMu.Unlock()
	runtimeUnlocked = true

	if len(userTraffic) > 0 {
		if err := flushUserTraffic(c.apiClient, c.config.DisableUploadTraffic, userTraffic, trafficDeltas); err != nil {
			log.Print(err)
		}
	}

	// Report Online info
	if onlineErr != nil {
		log.Print(onlineErr)
	} else if len(*onlineDevice) > 0 {
		if err = c.apiClient.ReportNodeOnlineUsers(onlineDevice); err != nil {
			log.Print(err)
		} else {
			log.Printf("%s Report %d online users", prefix, len(*onlineDevice))
		}
	}

	// Report Illegal user
	if detectErr != nil {
		log.Print(detectErr)
	} else if len(*detectResult) > 0 {
		if err = c.apiClient.ReportIllegal(detectResult); err != nil {
			log.Print(err)
		} else {
			log.Printf("%s Report %d illegal behaviors", prefix, len(*detectResult))
		}

	}
	return nil
}

func (c *Controller) buildNodeTag() string {
	return c.buildNodeTagFor(c.snapshot().nodeInfo)
}

func (c *Controller) buildNodeTagFor(nodeInfo *api.NodeInfo) string {
	if nodeInfo == nil {
		return ""
	}
	return fmt.Sprintf("%s_%s_%d", nodeInfo.NodeType, c.config.ListenIP, nodeInfo.Port)
}

func (c *Controller) logPrefix() string {
	state := c.snapshot()
	return logPrefixFor(state.clientInfo, state.nodeInfo)
}

func logPrefixFor(clientInfo api.ClientInfo, nodeInfo *api.NodeInfo) string {
	if nodeInfo == nil {
		return fmt.Sprintf("[%s] controller", clientInfo.APIHost)
	}
	return fmt.Sprintf("[%s] %s(ID=%d)", clientInfo.APIHost, nodeInfo.NodeType, nodeInfo.NodeID)
}

// Check Cert
func (c *Controller) certMonitor() error {
	state := c.snapshot()
	if state.nodeInfo != nil && state.nodeInfo.EnableTLS {
		switch c.config.CertConfig.CertMode {
		case "dns", "http", "tls":
			lego, err := mylego.New(c.config.CertConfig)
			if err != nil {
				log.Print(err)
			}
			// Xray-core supports the OcspStapling certification hot renew
			_, _, _, err = lego.RenewCert()
			if err != nil {
				log.Print(err)
			}
		}
	}
	return nil
}
