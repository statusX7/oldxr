package controller

import "github.com/XrayR-project/XrayR/api"

type retiringUserKey struct {
	tag   string
	email string
}

type retiringUser struct {
	tag  string
	user api.UserInfo
}

func (c *Controller) runtimeUserEmails(tag string, users *[]api.UserInfo) []string {
	if users == nil {
		return nil
	}
	emails := make([]string, len(*users))
	for i := range *users {
		emails[i] = c.buildUserTagWithTag(tag, &(*users)[i])
	}
	return emails
}

func (c *Controller) registerManagedUsers(tag string, users *[]api.UserInfo) {
	emails := c.runtimeUserEmails(tag, users)
	c.dispatcher.RegisterManagedUsers(tag, emails)
	c.stateMu.Lock()
	for _, email := range emails {
		delete(c.retiringUsers, retiringUserKey{tag: tag, email: email})
	}
	c.stateMu.Unlock()
}

func (c *Controller) retireManagedUsers(tag string, users *[]api.UserInfo) {
	if users == nil || len(*users) == 0 {
		return
	}
	emails := c.runtimeUserEmails(tag, users)
	c.dispatcher.RetireManagedUsers(tag, emails)
	c.stateMu.Lock()
	for i, email := range emails {
		c.retiringUsers[retiringUserKey{tag: tag, email: email}] = retiringUser{
			tag:  tag,
			user: (*users)[i],
		}
	}
	c.stateMu.Unlock()
}

func (c *Controller) restoreManagedUsers(tag string, users *[]api.UserInfo) {
	c.registerManagedUsers(tag, users)
}

func (c *Controller) retiringUserSnapshot() []retiringUser {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	users := make([]retiringUser, 0, len(c.retiringUsers))
	for _, user := range c.retiringUsers {
		users = append(users, user)
	}
	return users
}

func (c *Controller) finalizeRetiringUsers(users []retiringUser) {
	for _, retired := range users {
		email := c.buildUserTagWithTag(retired.tag, &retired.user)
		if !c.dispatcher.FinalizeRetiredUser(retired.tag, email) {
			continue
		}
		key := retiringUserKey{tag: retired.tag, email: email}
		c.stateMu.Lock()
		if current, ok := c.retiringUsers[key]; ok && current.user == retired.user {
			delete(c.retiringUsers, key)
		}
		c.stateMu.Unlock()
	}
}
