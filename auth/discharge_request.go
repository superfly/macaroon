package auth

import (
	"time"

	"github.com/superfly/macaroon/flyio"
	"golang.org/x/exp/maps"
)

// implements macaroon.Access
type DischargeRequest struct {
	Flyio  []*FlyioAuth
	Google []*GoogleAuth
	GitHub []*GitHubAuth
	Expiry time.Time
}

func (a *DischargeRequest) Now() time.Time  { return time.Now() }
func (a *DischargeRequest) Validate() error { return nil }

func (a *DischargeRequest) FlyioOrganizationIDs() []uint64 {
	m := map[uint64]struct{}{}
	for _, f := range a.Flyio {
		for _, om := range f.Memberships {
			m[om.OrganizationID] = struct{}{}
		}
	}

	return maps.Keys(m)
}

func (a *DischargeRequest) FlyioUserIDs() []uint64 {
	m := map[uint64]struct{}{}
	for _, f := range a.Flyio {
		m[f.UserID] = struct{}{}
	}

	return maps.Keys(m)
}

func (a *DischargeRequest) GoogleHDs() []string {
	m := map[string]struct{}{}
	for _, g := range a.Google {
		m[g.HD] = struct{}{}
	}

	return maps.Keys(m)
}

func (a *DischargeRequest) GitHubOrgIDs() []uint64 {
	m := map[uint64]struct{}{}
	for _, g := range a.GitHub {
		for _, o := range g.OrgIDs {
			m[o] = struct{}{}
		}
	}

	return maps.Keys(m)
}

type FlyioAuth struct {
	UserID      uint64
	Memberships []*FlyioMembership
}

type FlyioMembership struct {
	OrganizationID uint64
	Role           flyio.Role
}

type GoogleAuth struct {
	HD     string
	UserID *GoogleUserID // reuse attestation type for serialization
	Email  string
}

type GitHubAuth struct {
	OrgIDs []uint64
	UserID uint64
	Login  string
}
