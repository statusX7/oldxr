// Package rule is to control the audit rule behaviors
package rule

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

	mapset "github.com/deckarep/golang-set"

	"github.com/XrayR-project/XrayR/api"
)

type Manager struct {
	InboundRule         *sync.Map // Key: Tag, Value: []api.DetectRule
	InboundDetectResult *sync.Map // key: Tag, Value: mapset.NewSet []api.DetectResult
}

func New() *Manager {
	return &Manager{
		InboundRule:         new(sync.Map),
		InboundDetectResult: new(sync.Map),
	}
}

func (r *Manager) UpdateRule(tag string, newRuleList []api.DetectRule) error {
	if len(newRuleList) == 0 {
		r.InboundRule.Delete(tag)
		return nil
	}
	if value, ok := r.InboundRule.Load(tag); ok && sameRuleList(value.([]api.DetectRule), newRuleList) {
		return nil
	}
	// Detect reads published rules without holding a manager-wide lock. Copy
	// the slice so a panel adapter cannot reuse its backing array while a
	// connection is matching the previous snapshot.
	snapshot := append([]api.DetectRule(nil), newRuleList...)
	r.InboundRule.Store(tag, snapshot)
	return nil
}

func sameRuleList(old, new []api.DetectRule) bool {
	if len(old) != len(new) {
		return false
	}
	for i := range old {
		if old[i].ID != new[i].ID {
			return false
		}
		if old[i].Pattern == nil || new[i].Pattern == nil {
			if old[i].Pattern != new[i].Pattern {
				return false
			}
			continue
		}
		if old[i].Pattern.String() != new[i].Pattern.String() {
			return false
		}
	}
	return true
}

func (r *Manager) GetDetectResult(tag string) (*[]api.DetectResult, error) {
	detectResult := make([]api.DetectResult, 0)
	if value, ok := r.InboundDetectResult.LoadAndDelete(tag); ok {
		resultSet := value.(mapset.Set)
		it := resultSet.Iterator()
		for result := range it.C {
			detectResult = append(detectResult, result.(api.DetectResult))
		}
	}
	return &detectResult, nil
}

func (r *Manager) Detect(tag string, destination string, email string) (reject bool) {
	reject = false
	var hitRuleID = -1
	// If we have some rule for this inbound
	if value, ok := r.InboundRule.Load(tag); ok {
		ruleList := value.([]api.DetectRule)
		for _, r := range ruleList {
			if r.Pattern != nil && r.Pattern.MatchString(destination) {
				hitRuleID = r.ID
				reject = true
				break
			}
		}
		// If we hit some rule
		if reject && hitRuleID != -1 {
			separator := strings.LastIndexByte(email, '|')
			if separator < 0 || separator == len(email)-1 {
				newError(fmt.Sprintf("Record illegal behavior failed! Cannot find user's uid: %s", email)).AtDebug().WriteToLog()
				return reject
			}
			uid, err := strconv.Atoi(email[separator+1:])
			if err != nil {
				newError(fmt.Sprintf("Record illegal behavior failed! Cannot find user's uid: %s", email)).AtDebug().WriteToLog()
				return reject
			}
			newSet := mapset.NewSetWith(api.DetectResult{UID: uid, RuleID: hitRuleID})
			// If there are any hit history
			if v, ok := r.InboundDetectResult.LoadOrStore(tag, newSet); ok {
				resultSet := v.(mapset.Set)
				// If this is a new record
				if resultSet.Add(api.DetectResult{UID: uid, RuleID: hitRuleID}) {
					r.InboundDetectResult.Store(tag, resultSet)
				}
			}
		}
	}
	return reject
}
