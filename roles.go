package auth

import (
	"strings"
	"sync"
)

const (
	RoleAdmin = "admin"
)

type RoleSet interface {
	// Has checks if the role is in the set.
	Has(role string) bool
	// HasAny checks if any of the roles is in the set.
	HasAny(roles []string) bool
	// String returns a string representation of the set.
	String() string
	// List returns a list of roles in the set.
	List() []string
	// LoadFrom loads roles from a string representation.
	LoadFrom(s string) RoleSet
	// Add adds a role to the set.
	Add(role ...string) RoleSet
	// Remove removes a role from the set.
	Remove(role ...string) RoleSet
}

type roleSet struct {
	d map[string]bool
	m sync.RWMutex
}

func NewRoleSet() RoleSet {
	return &roleSet{
		d: make(map[string]bool),
	}
}

func (r *roleSet) Has(role string) bool {
	r.m.RLock()
	defer r.m.RUnlock()
	_, ok := r.d[role]
	return ok
}

func (r *roleSet) HasAny(roles []string) bool {
	r.m.RLock()
	defer r.m.RUnlock()
	for _, v := range roles {
		if r.Has(v) {
			return true
		}
	}
	return false
}

func (r *roleSet) String() string {
	r.m.RLock()
	defer r.m.RUnlock()
	return strings.Join(r.List(), ",")
}

func (r *roleSet) List() []string {
	r.m.RLock()
	defer r.m.RUnlock()
	result := make([]string, 0, len(r.d))
	for k, v := range r.d {
		if !v {
			continue
		}
		result = append(result, k)
	}

	return result
}

func (r *roleSet) LoadFrom(s string) RoleSet {
	r.m.Lock()
	defer r.m.Unlock()
	r.d = make(map[string]bool)
	roles := strings.Split(s, ",")
	for _, v := range roles {
		r.d[v] = true
	}
	return r
}

func (r *roleSet) Add(roles ...string) RoleSet {
	r.m.Lock()
	defer r.m.Unlock()
	for _, v := range roles {
		r.d[v] = true
	}
	return r
}

func (r *roleSet) Remove(roles ...string) RoleSet {
	r.m.Lock()
	defer r.m.Unlock()
	for _, v := range roles {
		delete(r.d, v)
	}
	return r
}
