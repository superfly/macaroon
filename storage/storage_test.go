package storage

import (
	"errors"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/superfly/macaroon"
	"github.com/superfly/macaroon/auth"
	"github.com/superfly/macaroon/resset"
)

var (
	storageServiceLocation   = "https://storage.fly"
	storageServiceSigningKey = macaroon.NewSigningKey()

	flyioLocation  = "https://api.fly.io/aaa/storage"
	flyioSharedKey = macaroon.NewEncryptionKey()

	storageAuthority = NewAuthority(storageServiceLocation, storageServiceSigningKey, map[string]macaroon.EncryptionKey{
		flyioLocation: flyioSharedKey,
	})
)

func TestObjectsCaveat(t *testing.T) {
	// generate a token limited to accessing a single bucket
	token, err := storageAuthority.IssueBucketToken(resset.ActionAll, "mybucket")
	assert.NoError(t, err)

	AssertAuthorized(t, token, &Access{
		Action:              resset.ActionRead,
		Object:              "https://storage.fly/mybucket/myobject",
		FlyioOrganizationID: 123,
	})

	// wrong bucket
	RefuteAuthorized(t, token, &Access{
		Action:              resset.ActionRead,
		Object:              "https://storage.fly/otherbucket/otherobject",
		FlyioOrganizationID: 123,
	})

	// further restrict the token to only reading a single object
	token, err = storageAuthority.AttenuateToken(token, RestrictObjects(
		resset.ActionRead,
		"https://storage.fly/mybucket/myobject",
	))
	assert.NoError(t, err)

	AssertAuthorized(t, token, &Access{
		Action:              resset.ActionRead,
		Object:              "https://storage.fly/mybucket/myobject",
		FlyioOrganizationID: 123,
	})

	// wrong action
	RefuteAuthorized(t, token, &Access{
		Action:              resset.ActionWrite,
		Object:              "https://storage.fly/mybucket/myobject",
		FlyioOrganizationID: 123,
	})

	// wrong object
	RefuteAuthorized(t, token, &Access{
		Action:              resset.ActionRead,
		Object:              "https://storage.fly/mybucket/otherobject",
		FlyioOrganizationID: 123,
	})
}

func TestThirdPartyFlow(t *testing.T) {
	var (
		fly = mockFlyio{}

		orgOne = uint64(123)
		orgTwo = uint64(234)

		userOne = mockUser{id: 1, orgIDs: []uint64{orgOne, orgTwo}}
		userTwo = mockUser{id: 2, orgIDs: []uint64{orgTwo}}
	)

	// Mint a token that requires an accompanying discharge token from fly.io.
	token, err := storageAuthority.IssueTokenForFlyioOrg(flyioLocation, orgOne)
	assert.NoError(t, err)

	// token doesn't work without discharge
	RefuteAuthorized(t, token, &Access{
		Action:              resset.ActionRead,
		Object:              "https://storage.fly/mybucket/myobject",
		FlyioOrganizationID: orgOne,
	})

	// the user is given their token. they extract the third party ticket and
	// request that fly.io issue them a discharge
	userToken := token
	ticket := userOne.extractThirdPartyTicket(t, userToken)

	discharge, err := fly.requestDischarge(userOne, ticket)
	assert.NoError(t, err)

	// the user adds their discharge token to their permission token and are now
	// able to access the storage service
	userToken = userToken + "," + discharge

	AssertAuthorized(t, userToken, &Access{
		Action:              resset.ActionRead,
		Object:              "https://storage.fly/mybucket/myobject",
		FlyioOrganizationID: orgOne,
	})

	// they're still limited to accessing objects belonging to the correct org
	RefuteAuthorized(t, userToken, &Access{
		Action:              resset.ActionRead,
		Object:              "https://storage.fly/otherbucket/otherobject",
		FlyioOrganizationID: orgTwo,
	})

	// the third party ticket instructed fly not to issue discharge tokens to
	// users who aren't members of orgOne.
	_, err = fly.requestDischarge(userTwo, ticket)
	assert.Error(t, err)
}

func AssertAuthorized(t *testing.T, token string, access *Access) {
	t.Helper()
	assert.NoError(t, storageAuthority.CheckToken(token, access))
}

func RefuteAuthorized(t *testing.T, token string, access *Access) {
	t.Helper()
	assert.Error(t, storageAuthority.CheckToken(token, access))
}

// fake fly.io user
type mockUser struct {
	id     uint64
	orgIDs []uint64
}

// the user is able to extract the third party "ticket" from their storage
// service token. The ticket (not the whole token) is sent to fly.io when
// requesting a discharge token.
func (mu mockUser) extractThirdPartyTicket(t *testing.T, token string) []byte {
	toks, err := macaroon.Parse(token)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(toks))

	ticket, err := macaroon.ThirdPartyTicket(toks[0], flyioLocation)
	assert.NoError(t, err)

	return ticket
}

// fake fly.io service capable of authenticating users and issuing discharge
// tokens.
type mockFlyio struct{}

// there's an actual discharge protocol
// (https://github.com/superfly/macaroon/blob/main/tp/README.md), but we do a
// simplified version here. This simulated a service that's able to authenticate
// the user and then provide them with a discharge token.
func (mf mockFlyio) requestDischarge(authenticatedUser mockUser, ticket []byte) (string, error) {
	ticketCaveats, discharge, err := macaroon.DischargeTicket(flyioSharedKey, flyioLocation, ticket)
	if err != nil {
		return "", err
	}

	// add attestation about what fly.io user the discharge is generated for
	user := auth.FlyioUserID(authenticatedUser.id)
	dischargeCaveats := []macaroon.Caveat{&user}

	for _, cav := range ticketCaveats {
		switch typed := cav.(type) {
		case *auth.ConfineOrganization:
			isMember := false
			for _, org := range authenticatedUser.orgIDs {
				if org == typed.ID {
					isMember = true
					break
				}
			}

			if !isMember {
				return "", errors.New("refusing to discharge ticket. not member of correct org")
			}
		case *auth.MaxValidity:
			dischargeCaveats = append(dischargeCaveats, &macaroon.ValidityWindow{
				NotBefore: time.Now().Unix(),
				NotAfter:  time.Now().Add(typed.Duration()).Unix(),
			})
		default:
			return "", errors.New("unexpected caveat in ticket")
		}
	}

	if err := discharge.Add(dischargeCaveats...); err != nil {
		return "", nil
	}

	return discharge.String()
}
