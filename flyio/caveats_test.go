package flyio

import (
	"encoding/json"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/superfly/macaroon"
	"github.com/superfly/macaroon/resset"
)

func TestCaveatSerialization(t *testing.T) {
	cs := macaroon.NewCaveatSet(
		&Organization{ID: 123, Mask: resset.ActionRead},
		&Apps{Apps: resset.ResourceSet[uint64]{123: resset.ActionRead}},
		&FeatureSet{Features: resset.New(resset.ActionRead, "123")},
		&Volumes{Volumes: resset.New(resset.ActionRead, "123")},
		&Machines{Machines: resset.New(resset.ActionRead, "123")},
		&Mutations{Mutations: []string{"123"}},
		&IsUser{ID: 123},
		&MachineFeatureSet{Features: resset.New(resset.ActionRead, "123")},
		&FromMachine{ID: "asdf"},
		&Clusters{Clusters: resset.New(resset.ActionRead, "123")},
		&NoAdminFeatures{},
	)

	b, err := json.Marshal(cs)
	assert.NoError(t, err)

	cs2 := macaroon.NewCaveatSet()
	err = json.Unmarshal(b, cs2)
	assert.NoError(t, err)
	assert.Equal(t, cs, cs2)

	b, err = cs.MarshalMsgpack()
	assert.NoError(t, err)
	cs2, err = macaroon.DecodeCaveats(b)
	assert.NoError(t, err)
	assert.Equal(t, cs, cs2)
}

func TestNoAdminFeatures(t *testing.T) {
	cs := macaroon.NewCaveatSet(&NoAdminFeatures{})

	yes := func(access *Access) {
		t.Helper()
		assert.NoError(t, cs.Validate(access))
	}

	no := func(access *Access, target error) {
		t.Helper()
		err := cs.Validate(access)
		assert.Error(t, err)
		assert.IsError(t, err, target)
	}

	yes(&Access{
		OrgID:   uptr(1),
		Action:  resset.ActionAll,
		Feature: ptr("wg"),
	})

	yes(&Access{
		OrgID:   uptr(1),
		Action:  resset.ActionRead,
		Feature: ptr("membership"),
	})

	yes(&Access{
		OrgID:  uptr(1),
		Action: resset.ActionAll,
	})

	no(&Access{
		OrgID:   uptr(1),
		Action:  resset.ActionWrite,
		Feature: ptr("membership"),
	}, resset.ErrUnauthorizedForAction)

	no(&Access{
		OrgID:   uptr(1),
		Action:  resset.ActionRead,
		Feature: ptr("unknown"),
	}, resset.ErrUnauthorizedForResource)

	no(&Access{
		OrgID:   uptr(1),
		Action:  resset.ActionNone,
		Feature: ptr(""),
	}, resset.ErrUnauthorizedForResource)

	no(&Access{
		OrgID:   uptr(1),
		Action:  resset.ActionNone,
		Feature: ptr(""),
	}, resset.ErrUnauthorizedForResource)
}
