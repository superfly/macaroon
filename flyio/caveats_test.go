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
		&IsMember{},
		ptr(AllowedRoles(RoleAdmin)),
		&Commands{Command{[]string{"123"}, true}},
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

func TestAllowedRoles(t *testing.T) {
	csMember := macaroon.NewCaveatSet(&IsMember{})
	csAdmin := macaroon.NewCaveatSet(ptr(AllowedRoles(RoleAdmin)))

	yes := func(cs *macaroon.CaveatSet, access *Access) {
		t.Helper()
		assert.NoError(t, cs.Validate(access))
	}

	no := func(cs *macaroon.CaveatSet, access *Access, target error) {
		t.Helper()
		err := cs.Validate(access)
		assert.Error(t, err)
		assert.IsError(t, err, target)
	}

	yes(csMember, &Access{
		OrgID:   uptr(1),
		Action:  resset.ActionAll,
		Feature: ptr("wg"),
	})
	yes(csAdmin, &Access{
		OrgID:   uptr(1),
		Action:  resset.ActionAll,
		Feature: ptr("wg"),
	})

	yes(csMember, &Access{
		OrgID:   uptr(1),
		Action:  resset.ActionRead,
		Feature: ptr("membership"),
	})
	yes(csAdmin, &Access{
		OrgID:   uptr(1),
		Action:  resset.ActionRead,
		Feature: ptr("membership"),
	})

	yes(csMember, &Access{
		OrgID:  uptr(1),
		Action: resset.ActionAll,
	})
	yes(csAdmin, &Access{
		OrgID:  uptr(1),
		Action: resset.ActionAll,
	})

	no(csMember, &Access{
		OrgID:   uptr(1),
		Action:  resset.ActionWrite,
		Feature: ptr("membership"),
	}, ErrUnauthorizedForRole)
	yes(csAdmin, &Access{
		OrgID:   uptr(1),
		Action:  resset.ActionWrite,
		Feature: ptr("membership"),
	})

	no(csMember, &Access{
		OrgID:   uptr(1),
		Action:  resset.ActionRead,
		Feature: ptr("unknown"),
	}, ErrUnauthorizedForRole)
	yes(csAdmin, &Access{
		OrgID:   uptr(1),
		Action:  resset.ActionRead,
		Feature: ptr("unknown"),
	})

	no(csMember, &Access{
		OrgID:   uptr(1),
		Action:  resset.ActionNone,
		Feature: ptr(""),
	}, ErrUnauthorizedForRole)
	yes(csAdmin, &Access{
		OrgID:   uptr(1),
		Action:  resset.ActionNone,
		Feature: ptr(""),
	})

	no(csMember, &Access{
		OrgID:   uptr(1),
		Action:  resset.ActionNone,
		Feature: ptr(""),
	}, ErrUnauthorizedForRole)
	yes(csAdmin, &Access{
		OrgID:   uptr(1),
		Action:  resset.ActionNone,
		Feature: ptr(""),
	})
}

func TestRole(t *testing.T) {
	assert.Equal(t, "admin", RoleAdmin.String())
	assert.Equal(t, "member", RoleMember.String())
	assert.Equal(t, "member+billing_manager", (RoleMember | RoleBillingManager).String())

	assert.True(t, RoleAdmin.HasAllRoles(RoleAdmin))
	assert.True(t, RoleAdmin.HasAllRoles(RoleMember))
	assert.False(t, RoleMember.HasAllRoles(RoleAdmin))
	assert.False(t, RoleMember.HasAllRoles(RoleBillingManager))
}

func TestCommands(t *testing.T) {
	yes := func(cs *macaroon.CaveatSet, access *Access) {
		t.Helper()
		assert.NoError(t, cs.Validate(access))
	}

	no := func(cs *macaroon.CaveatSet, access *Access, target error) {
		t.Helper()
		err := cs.Validate(access)
		assert.Error(t, err)
		assert.IsError(t, err, target)
	}

	cs := macaroon.NewCaveatSet(&Commands{
		Command{[]string{"cmd1", "arg1"}, false},
		Command{[]string{"cmd2", "arg1"}, true},
	})

	yes(cs, &Access{
		OrgID:   uptr(1),
		AppID:   uptr(1),
		Machine: ptr("machine"),
		Command: []string{"cmd1", "arg1"},
	})

	yes(cs, &Access{
		OrgID:   uptr(1),
		Action:  resset.ActionAll,
		AppID:   uptr(1),
		Machine: ptr("machine"),
		Command: []string{"cmd1", "arg1", "arg2"},
	})

	yes(cs, &Access{
		OrgID:   uptr(1),
		AppID:   uptr(1),
		Machine: ptr("machine"),
		Action:  resset.ActionAll,
		Command: []string{"cmd2", "arg1"},
	})

	no(cs, &Access{
		OrgID:   uptr(1),
		AppID:   uptr(1),
		Machine: ptr("machine"),
		Action:  resset.ActionAll,
		Command: []string{"cmd2", "arg1", "arg2"},
	}, resset.ErrUnauthorizedForResource)

	no(cs, &Access{
		OrgID:   uptr(1),
		AppID:   uptr(1),
		Machine: ptr("machine"),
		Action:  resset.ActionAll,
		Command: []string{"cmd3", "arg1"},
	}, resset.ErrUnauthorizedForResource)

	no(cs, &Access{
		OrgID:   uptr(1),
		AppID:   uptr(1),
		Machine: ptr("machine"),
		Action:  resset.ActionAll,
	}, resset.ErrResourceUnspecified)

	csNone := macaroon.NewCaveatSet(&Commands{})

	no(csNone, &Access{
		OrgID:   uptr(1),
		AppID:   uptr(1),
		Machine: ptr("machine"),
		Action:  resset.ActionAll,
		Command: []string{"cmd2", "arg1", "arg2", "arg3"},
	}, resset.ErrUnauthorizedForResource)

	no(csNone, &Access{
		OrgID:   uptr(1),
		AppID:   uptr(1),
		Machine: ptr("machine"),
		Action:  resset.ActionAll,
	}, resset.ErrResourceUnspecified)

	csAny := macaroon.NewCaveatSet(&Commands{Command{}})

	yes(csAny, &Access{
		OrgID:   uptr(1),
		AppID:   uptr(1),
		Machine: ptr("machine"),
		Action:  resset.ActionAll,
		Command: []string{"cmd2", "arg1", "arg2", "arg3"},
	})

	no(csAny, &Access{
		OrgID:   uptr(1),
		AppID:   uptr(1),
		Machine: ptr("machine"),
		Action:  resset.ActionAll,
	}, resset.ErrResourceUnspecified)

	csIf := macaroon.NewCaveatSet(
		&resset.IfPresent{
			Ifs:  macaroon.NewCaveatSet(&Commands{Command{}}),
			Else: resset.ActionDelete,
		},
	)

	yes(csIf, &Access{
		OrgID:   uptr(1),
		AppID:   uptr(1),
		Machine: ptr("machine"),
		Action:  resset.ActionNone,
		Command: []string{"uname", "arg"},
	})

	yes(csIf, &Access{
		OrgID:   uptr(1),
		AppID:   uptr(1),
		Machine: ptr("machine"),
		Action:  resset.ActionDelete,
	})

	no(csIf, &Access{
		OrgID:   uptr(1),
		AppID:   uptr(1),
		Machine: ptr("machine"),
		Action:  resset.ActionWrite,
	}, resset.ErrUnauthorizedForAction)
}
