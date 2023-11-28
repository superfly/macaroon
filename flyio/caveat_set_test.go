package flyio

import (
	"errors"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/superfly/macaroon"
	"github.com/superfly/macaroon/resset"
)

func TestScopeOrganizationID(t *testing.T) {
	// error if not org constrained
	_, err := OrganizationScope(macaroon.NewCaveatSet(
		&Apps{resset.ResourceSet[uint64]{123: resset.ActionAll}},
	))

	assert.True(t, errors.Is(err, macaroon.ErrUnauthorized))

	// err if multiple orgs specified
	_, err = OrganizationScope(macaroon.NewCaveatSet(
		&Organization{ID: 123, Mask: resset.ActionAll},
		&Organization{ID: 234, Mask: resset.ActionAll},
	))

	assert.True(t, errors.Is(err, resset.ErrUnauthorizedForResource))

	// err if second org is specified in IfPresent
	_, err = OrganizationScope(macaroon.NewCaveatSet(
		&Organization{ID: 123, Mask: resset.ActionAll},
		&resset.IfPresent{Ifs: macaroon.NewCaveatSet(&Organization{ID: 234, Mask: resset.ActionAll})},
	))

	assert.True(t, errors.Is(err, resset.ErrUnauthorizedForResource))

	// ok - basic
	id, err := OrganizationScope(macaroon.NewCaveatSet(
		&Organization{ID: 123, Mask: resset.ActionAll},
	))

	assert.NoError(t, err)
	assert.Equal(t, 123, id)

	// ok - no permission allowed
	_, err = OrganizationScope(macaroon.NewCaveatSet(
		&Organization{ID: 123, Mask: resset.ActionNone},
	))

	assert.NoError(t, err)

	// ok - no permission allowed by IfPresent
	_, err = OrganizationScope(macaroon.NewCaveatSet(
		&Organization{ID: 123, Mask: resset.ActionAll},
		&resset.IfPresent{Else: resset.ActionNone, Ifs: macaroon.NewCaveatSet(&Apps{resset.ResourceSet[uint64]{123: resset.ActionAll}})},
	))

	assert.NoError(t, err)

	// ok - some child resource is required
	id, err = OrganizationScope(macaroon.NewCaveatSet(
		&Organization{ID: 123, Mask: resset.ActionAll},
		&Apps{resset.ResourceSet[uint64]{234: resset.ActionAll}},
	))

	assert.NoError(t, err)
	assert.Equal(t, 123, id)
}

func TestAppIDs(t *testing.T) {
	var (
		empty         = []uint64{}
		unconstrained = ([]uint64)(nil)
		constrained   = []uint64{1}
	)

	// try each case with a id=* caveat, which should be a noop for scoping.
	bases := [][]macaroon.Caveat{
		{},
		{&Apps{resset.ResourceSet[uint64]{0: resset.ActionAll}}},
		{&Apps{resset.ResourceSet[uint64]{0: resset.ActionNone}}},
	}

	for _, base := range bases {
		// {} for empty Apps
		ids := AppScope(macaroon.NewCaveatSet(append(base,
			&Apps{},
		)...))

		assert.Equal(t, empty, ids)

		// {} for empty IfPresent
		ids = AppScope(macaroon.NewCaveatSet(append(base,
			&resset.IfPresent{Ifs: macaroon.NewCaveatSet(&Apps{})},
		)...))

		assert.Equal(t, empty, ids)

		// {} for disjoint Apps
		ids = AppScope(macaroon.NewCaveatSet(append(base,
			&Apps{resset.ResourceSet[uint64]{1: resset.ActionRead}},
			&Apps{resset.ResourceSet[uint64]{2: resset.ActionRead}},
		)...))

		assert.Equal(t, empty, ids)

		// {} for disjoint Apps/IfPresent
		ids = AppScope(macaroon.NewCaveatSet(append(base,
			&Apps{resset.ResourceSet[uint64]{1: resset.ActionRead}},
			&resset.IfPresent{Ifs: macaroon.NewCaveatSet(&Apps{resset.ResourceSet[uint64]{2: resset.ActionRead}})},
		)...))

		assert.Equal(t, empty, ids)

		// {} for disjoint IfPresents
		ids = AppScope(macaroon.NewCaveatSet(append(base,
			&resset.IfPresent{Ifs: macaroon.NewCaveatSet(&Apps{resset.ResourceSet[uint64]{1: resset.ActionRead}})},
			&resset.IfPresent{Ifs: macaroon.NewCaveatSet(&Apps{resset.ResourceSet[uint64]{2: resset.ActionRead}})},
		)...))

		assert.Equal(t, empty, ids)

		// nil if app unconstrained
		ids = AppScope(macaroon.NewCaveatSet(base...))

		assert.Equal(t, unconstrained, ids)

		// nil if app unconstrained and has unrelated caveats
		ids = AppScope(macaroon.NewCaveatSet(append(base,
			&resset.IfPresent{Else: resset.ActionRead, Ifs: macaroon.NewCaveatSet(&FeatureSet{resset.ResourceSet[string]{"wg": resset.ActionAll}})},
		)...))

		assert.Equal(t, unconstrained, ids)

		// {123} if app constrained
		ids = AppScope(macaroon.NewCaveatSet(append(base,
			&Apps{resset.ResourceSet[uint64]{1: resset.ActionRead}},
		)...))

		assert.Equal(t, constrained, ids)

		// {123} if no permissions allowed on app
		ids = AppScope(macaroon.NewCaveatSet(append(base,
			&Apps{resset.ResourceSet[uint64]{1: resset.ActionNone}},
		)...))

		assert.Equal(t, constrained, ids)

		// {123} if disjoint permissions allowed on app
		ids = AppScope(macaroon.NewCaveatSet(append(base,
			&Apps{resset.ResourceSet[uint64]{1: resset.ActionRead}},
			&Apps{resset.ResourceSet[uint64]{1: resset.ActionWrite}},
		)...))

		assert.Equal(t, constrained, ids)

		// {123} if app constrained by IfPresent
		ids = AppScope(macaroon.NewCaveatSet(append(base,
			&resset.IfPresent{Else: resset.ActionRead, Ifs: macaroon.NewCaveatSet(&Apps{resset.ResourceSet[uint64]{1: resset.ActionRead}})},
		)...))

		assert.Equal(t, constrained, ids)

		// {123} if app constrained and other IfPresent
		ids = AppScope(macaroon.NewCaveatSet(append(base,
			&Apps{resset.ResourceSet[uint64]{1: resset.ActionAll}},
			&resset.IfPresent{Else: resset.ActionNone, Ifs: macaroon.NewCaveatSet(&FeatureSet{resset.ResourceSet[string]{"wg": resset.ActionAll}})},
		)...))

		assert.Equal(t, constrained, ids)
	}
}

func TestClusters(t *testing.T) {
	var (
		empty       = []string{}
		constrained = []string{"1"}
	)

	// {} for empty Clusters
	ids := ClusterScope(macaroon.NewCaveatSet(&Clusters{}))
	assert.Equal(t, empty, ids)

	// {} for empty IfPresent
	ids = ClusterScope(macaroon.NewCaveatSet(&resset.IfPresent{Ifs: macaroon.NewCaveatSet(&Clusters{})}))
	assert.Equal(t, empty, ids)

	// {} for disjoint Clusters
	ids = ClusterScope(macaroon.NewCaveatSet(&Clusters{resset.ResourceSet[string]{"1": resset.ActionRead}}, &Clusters{resset.ResourceSet[string]{"2": resset.ActionRead}}))
	assert.Equal(t, empty, ids)

	// {} for disjoint Clusters/IfPresent
	ids = ClusterScope(macaroon.NewCaveatSet(&Clusters{resset.ResourceSet[string]{"1": resset.ActionRead}}, &resset.IfPresent{Ifs: macaroon.NewCaveatSet(&Clusters{resset.ResourceSet[string]{"2": resset.ActionRead}})}))
	assert.Equal(t, empty, ids)

	// {} for disjoint IfPresents
	ids = ClusterScope(macaroon.NewCaveatSet(
		&resset.IfPresent{Ifs: macaroon.NewCaveatSet(&Clusters{resset.ResourceSet[string]{"1": resset.ActionRead}})},
		&resset.IfPresent{Ifs: macaroon.NewCaveatSet(&Clusters{resset.ResourceSet[string]{"2": resset.ActionRead}})},
	))
	assert.Equal(t, empty, ids)

	// {123} if cluster constrained
	ids = ClusterScope(macaroon.NewCaveatSet(&Clusters{resset.ResourceSet[string]{"1": resset.ActionRead}}))
	assert.Equal(t, constrained, ids)

	// {123} if no permissions allowed on cluster
	ids = ClusterScope(macaroon.NewCaveatSet(&Clusters{resset.ResourceSet[string]{"1": resset.ActionNone}}))
	assert.Equal(t, constrained, ids)

	// {123} if disjoint permissions allowed on cluster
	ids = ClusterScope(macaroon.NewCaveatSet(&Clusters{resset.ResourceSet[string]{"1": resset.ActionRead}}, &Clusters{resset.ResourceSet[string]{"1": resset.ActionWrite}}))
	assert.Equal(t, constrained, ids)

	// {123} if cluster constrained by IfPresent
	ids = ClusterScope(macaroon.NewCaveatSet(&resset.IfPresent{Else: resset.ActionRead, Ifs: macaroon.NewCaveatSet(&Clusters{resset.ResourceSet[string]{"1": resset.ActionRead}})}))
	assert.Equal(t, constrained, ids)

	// {123} if cluster constrained and other IfPresent
	ids = ClusterScope(macaroon.NewCaveatSet(
		&Clusters{resset.ResourceSet[string]{"1": resset.ActionAll}},
		&resset.IfPresent{Else: resset.ActionNone, Ifs: macaroon.NewCaveatSet(&FeatureSet{resset.ResourceSet[string]{"wg": resset.ActionAll}})},
	))
	assert.Equal(t, constrained, ids)
}

func TestAppsAllowing(t *testing.T) {
	// OrganizationScope error
	_, _, err := AppsAllowing(macaroon.NewCaveatSet(
		&Apps{resset.ResourceSet[uint64]{123: resset.ActionAll}},
	), resset.ActionNone)

	assert.True(t, errors.Is(err, macaroon.ErrUnauthorized))

	// ⦰ apps
	_, _, err = AppsAllowing(macaroon.NewCaveatSet(
		&Organization{ID: 987, Mask: resset.ActionAll},
		&Apps{},
	), resset.ActionNone)

	assert.True(t, errors.Is(err, resset.ErrUnauthorizedForResource))

	// action prohibited on org
	_, _, err = AppsAllowing(macaroon.NewCaveatSet(
		&Organization{ID: 987, Mask: resset.ActionRead},
	), resset.ActionWrite)

	assert.True(t, errors.Is(err, resset.ErrUnauthorizedForAction))

	// action prohibited on all apps
	_, _, err = AppsAllowing(macaroon.NewCaveatSet(
		&Organization{ID: 987, Mask: resset.ActionAll},
		&Apps{resset.ResourceSet[uint64]{123: resset.ActionRead}},
	), resset.ActionWrite)

	assert.True(t, errors.Is(err, resset.ErrUnauthorizedForAction))

	// action allowed on org
	orgID, appIDs, err := AppsAllowing(macaroon.NewCaveatSet(
		&Organization{ID: 987, Mask: resset.ActionAll},
	), resset.ActionWrite)

	assert.NoError(t, err)
	assert.Equal(t, 987, orgID)
	assert.Equal(t, nil, appIDs)

	// action allowed on some apps
	orgID, appIDs, err = AppsAllowing(macaroon.NewCaveatSet(
		&Organization{ID: 987, Mask: resset.ActionAll},
		&Apps{Apps: resset.ResourceSet[uint64]{123: resset.ActionAll, 234: resset.ActionWrite, 345: resset.ActionRead}},
	), resset.ActionWrite)

	assert.NoError(t, err)
	assert.Equal(t, 987, orgID)
	assert.Equal(t, []uint64{123, 234}, appIDs)
}
