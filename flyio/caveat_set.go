package flyio

import (
	"fmt"
	"slices"

	"github.com/superfly/macaroon"
	"github.com/superfly/macaroon/resset"
	"golang.org/x/exp/constraints"
	"golang.org/x/exp/maps"
)

// trickery  to allow passing slice of specific Caveat types
func typedCaveatSet[T macaroon.Caveat](caveats ...T) *macaroon.CaveatSet {
	cavs := make([]macaroon.Caveat, 0, len(caveats))
	for _, c := range caveats {
		cavs = append(cavs, c)
	}

	return macaroon.NewCaveatSet(cavs...)
}

// OrganizationScope finds the ID of the organization that application queries
// should be scoped to. This doesn't imply any specific access to the
// organization, since it disregards caveats requiring specific child
// resources and doesn't check for any level of access.
func OrganizationScope(cs *macaroon.CaveatSet) (uint64, error) {
	cavs := macaroon.GetCaveats[*Organization](cs)
	if len(cavs) == 0 {
		return 0, fmt.Errorf("%w: token must be constrained to org", macaroon.ErrUnauthorized)
	}

	orgCS := typedCaveatSet(cavs...)

	if err := orgCS.Validate(&Access{DeprecatedOrgID: &cavs[0].ID, Action: resset.ActionNone}); err != nil {
		return 0, err
	}

	return cavs[0].ID, nil
}

// AppScope finds the IDs of the apps that application queries should be scoped
// to. This doesn't imply any specific access to the apps, since it disregards
// caveats requiring specific child/sibling resources and doesn't check for
// any level of access.
func AppScope(cs *macaroon.CaveatSet) []uint64 {
	cavs := macaroon.GetCaveats[*Apps](cs)
	if len(cavs) == 0 {
		return nil
	}

	// gather any app id mentioned in any caveat
	possibleIDs := map[uint64]bool{}
	for _, cav := range cavs {
		for id := range cav.Apps {
			possibleIDs[id] = true
		}
	}

	// remove app ids that aren't in all caveats
	appCS := typedCaveatSet(cavs...)
	maps.DeleteFunc(possibleIDs, func(id uint64, _ bool) bool {
		err := appCS.Validate(&Access{
			DeprecatedOrgID: ptr(uint64(999)), // access requires an org
			Action:          resset.ActionNone,
			DeprecatedAppID: &id,
		})

		return err != nil
	})

	// do we allow id=0 (aka id=*)?
	if possibleIDs[0] {
		return nil
	}

	// map ordering is random. sort for consistency in tests.
	ret := maps.Keys(possibleIDs)
	slices.Sort(ret)

	return ret
}

// ClusterScope finds the IDs of the clusters that clusters queries should be scoped
// to. This doesn't imply any specific access to the clusters , since it disregards
// caveats requiring specific child/sibling resources and doesn't check for
// any level of access.
func ClusterScope(cs *macaroon.CaveatSet) []string {
	cavs := macaroon.GetCaveats[*Clusters](cs)
	if len(cavs) == 0 {
		return nil
	}

	// gather any cluster id mentioned in any caveat
	possibleIDs := map[string]bool{}
	for _, cav := range cavs {
		for id := range cav.Clusters {
			possibleIDs[id] = true
		}
	}

	// remove clusters ids that aren't in all caveats
	clusterCS := typedCaveatSet(cavs...)
	maps.DeleteFunc(possibleIDs, func(id string, _ bool) bool {
		err := clusterCS.Validate(&Access{
			DeprecatedOrgID: ptr(uint64(999)), // access requires an org
			Action:          resset.ActionNone,
			Feature:         ptr(FeatureLFSC),
			Cluster:         &id,
		})

		return err != nil
	})

	// map ordering is random. sort for consistency in tests.
	ret := maps.Keys(possibleIDs)
	slices.Sort(ret)

	return ret
}

// WARNING: it is the caller's responsibility to ensure that apps actually
// belong to the organization before completing an operation for the user!
//
// AppsAllowing gets the set of apps that allow the specified action. An
// organization ID and a slice of app IDs are returned. A nil slice means that
// the action is allowed on any org-owned app, which an empty slice (which
// won't be returned without an accompanying error) means that the action isn't
// allowed on any apps.
func AppsAllowing(cs *macaroon.CaveatSet, action resset.Action) (uint64, []uint64, error) {
	empty := []uint64{}

	orgScope, err := OrganizationScope(cs)
	if err != nil {
		return 0, empty, err
	}

	appScope := AppScope(cs)

	// no app restrictions, check that action is allowed on apps in general
	if appScope == nil {
		var zeroID uint64
		if err := cs.Validate(&Access{DeprecatedOrgID: &orgScope, DeprecatedAppID: &zeroID, Action: action}); err != nil {
			return 0, empty, err
		}
		return orgScope, nil, nil
	}

	// no apps in scope
	if len(appScope) == 0 {
		return 0, empty, fmt.Errorf("%w: %s not allowed for any apps", resset.ErrUnauthorizedForResource, action)
	}

	// filter scope to those allowing action
	ret := make([]uint64, 0, len(appScope))
	for _, appID := range appScope {
		if err := cs.Validate(&Access{DeprecatedOrgID: &orgScope, DeprecatedAppID: &appID, Action: action}); err == nil {
			ret = append(ret, appID)
		}
	}

	if len(ret) == 0 {
		return 0, empty, fmt.Errorf("%w: %s not allowed for any apps", resset.ErrUnauthorizedForAction, action)
	}

	// map ordering is random. sort for consistency in tests.
	slices.Sort(ret)

	return orgScope, ret, nil
}

func ptr[T any](v T) *T {
	return &v
}

func uptr[T constraints.Integer](v T) *uint64 {
	return ptr(uint64(v))
}
