package auth

import "time"

// implements macaroon.Access
type DischargeRequest struct {
	User         *UserAuth
	Organization *OrganizationAuth
	Google       *GoogleAuth
	GitHub       *GitHubAuth
	Expiry       time.Time
}

func (a *DischargeRequest) Now() time.Time  { return time.Now() }
func (a *DischargeRequest) Validate() error { return nil }

type UserAuth struct {
	ID uint64
}

type OrganizationAuth struct {
	IDs []uint64
}

type GoogleAuth struct {
	HD string
}

type GitHubAuth struct {
	OrgIDs []uint64
}
