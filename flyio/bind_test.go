package flyio

import (
	"crypto/sha256"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/superfly/macaroon"
	"github.com/superfly/macaroon/resset"
)

func newPermissionMacaroon(t *testing.T) (*macaroon.Macaroon, macaroon.SigningKey) {
	key := macaroon.NewSigningKey()
	digest := sha256.Sum256(key)
	kid := digest[:16]

	m, err := macaroon.New(kid, LocationPermission, key)
	assert.NoError(t, err)

	return m, key
}

func TestBindBeforeAttenuate(t *testing.T) {
	m, key := newPermissionMacaroon(t)

	ka := macaroon.NewEncryptionKey()

	m.Add(&Organization{
		ID:   123,
		Mask: resset.ActionAll,
	})

	err := m.Add3P(ka, LocationAuthentication)
	assert.NoError(t, err)

	tickets := m.TicketsForThirdParty(LocationAuthentication)
	assert.Equal(t, 1, len(tickets))

	_, dm, err := macaroon.DischargeTicket(ka, LocationAuthentication, tickets[0])
	assert.NoError(t, err)

	err = dm.BindToParentMacaroon(m)
	assert.NoError(t, err)

	dis, err := dm.Encode()
	assert.NoError(t, err)

	_, err = m.Verify(key, nil, nil)
	assert.EqualError(t, err, "no matching discharge token")

	cs, err := m.Verify(key, [][]byte{dis}, nil)
	assert.NoError(t, err)

	err = cs.Validate(&Access{
		Action: resset.ActionRead,
		OrgID:  ptr(uint64(123)),
	})
	assert.NoError(t, err)

	err = cs.Validate(&Access{
		Action: resset.ActionRead,
		OrgID:  ptr(uint64(456)),
	})
	assert.EqualError(t, err, "unauthorized for org 456, only 123")

	m.Add(&Apps{
		Apps: resset.New(resset.ActionAll, uint64(123)),
	})

	_, err = m.Verify(key, nil, nil)
	assert.EqualError(t, err, "no matching discharge token")

	// This still works because the discharge is bound to the previous tail, but not the new tail
	cs, err = m.Verify(key, [][]byte{dis}, nil)
	assert.NoError(t, err)

	err = cs.Validate(&Access{
		Action: resset.ActionRead,
		OrgID:  ptr(uint64(123)),
		AppID:  ptr(uint64(123)),
	})
	assert.NoError(t, err)

	err = cs.Validate(&Access{
		Action: resset.ActionRead,
		OrgID:  ptr(uint64(123)),
		AppID:  ptr(uint64(456)),
	})
	assert.EqualError(t, err, "unauthorized for app 456 (only [123])")
}

func TestBindAfterSplitting(t *testing.T) {
	m, key := newPermissionMacaroon(t)

	ka := macaroon.NewEncryptionKey()

	m.Add(&Organization{
		ID:   123,
		Mask: resset.ActionAll,
	})

	err := m.Add3P(ka, LocationAuthentication)
	assert.NoError(t, err)

	// make two macaroons which share the same prefix including the 3p caveat.
	m2, err := m.Clone()
	assert.NoError(t, err)

	m.Add(&Apps{
		Apps: resset.New(resset.ActionAll, uint64(123)),
	})

	m2.Add(&Apps{
		Apps: resset.New(resset.ActionAll, uint64(321)),
	})

	// discharge both macaroons separately
	tickets := m.TicketsForThirdParty(LocationAuthentication)
	assert.Equal(t, 1, len(tickets))

	_, dm, err := macaroon.DischargeTicket(ka, LocationAuthentication, tickets[0])
	assert.NoError(t, err)

	err = dm.BindToParentMacaroon(m)
	assert.NoError(t, err)

	dis, err := dm.Encode()
	assert.NoError(t, err)
	//assert.True(t, m.DischargeIsOurs(dis))

	tickets = m.TicketsForThirdParty(LocationAuthentication)
	assert.Equal(t, 1, len(tickets))

	_, dm, err = macaroon.DischargeTicket(ka, LocationAuthentication, tickets[0])
	assert.NoError(t, err)

	err = dm.BindToParentMacaroon(m2)
	assert.NoError(t, err)

	dis2, err := dm.Encode()
	assert.NoError(t, err)
	//assert.True(t, m2.DischargeIsOurs(dis2))
	//assert.False(t, m.DischargeIsOurs(dis2))
	//assert.False(t, m2.DischargeIsOurs(dis))

	// cant verify m or m2 without discharge
	_, err = m.Verify(key, nil, nil)
	assert.EqualError(t, err, "no matching discharge token")

	_, err = m2.Verify(key, nil, nil)
	assert.EqualError(t, err, "no matching discharge token")

	// can verify m and m2 with their respective discharges
	_, err = m.Verify(key, [][]byte{dis}, nil)
	assert.NoError(t, err)

	_, err = m2.Verify(key, [][]byte{dis2}, nil)
	assert.NoError(t, err)

	// cant verify m with m2's disch or m2 with m's disch.
	_, err = m2.Verify(key, [][]byte{dis}, nil)
	assert.Contains(t, err.Error(), "discharge bound to different parent token")

	_, err = m.Verify(key, [][]byte{dis2}, nil)
	assert.Contains(t, err.Error(), "discharge bound to different parent token")

	// can verify m and m2 with both discharges
	_, err = m.Verify(key, [][]byte{dis, dis2}, nil)
	assert.NoError(t, err)

	_, err = m2.Verify(key, [][]byte{dis, dis2}, nil)
	assert.NoError(t, err)

	// can verify m and m2 with both discharges as would be done if both m
	// and m2 and their discharges were passed as a single token bundle.
	cs, err := m.Verify(key, [][]byte{dis, dis2}, nil)
	assert.NoError(t, err)

	cs2, err := m2.Verify(key, [][]byte{dis, dis2}, nil)
	assert.NoError(t, err)

	// m allows apps app123
	err = cs.Validate(&Access{
		Action: resset.ActionRead,
		OrgID:  ptr(uint64(123)),
		AppID:  ptr(uint64(123)),
	})
	assert.NoError(t, err)

	// m2 allows apps app321
	err = cs2.Validate(&Access{
		Action: resset.ActionRead,
		OrgID:  ptr(uint64(123)),
		AppID:  ptr(uint64(321)),
	})
	assert.NoError(t, err)

	// m2 does not allow app123
	err = cs2.Validate(&Access{
		Action: resset.ActionRead,
		OrgID:  ptr(uint64(123)),
		AppID:  ptr(uint64(123)),
	})
	assert.EqualError(t, err, "unauthorized for app 123 (only [321])")
}
