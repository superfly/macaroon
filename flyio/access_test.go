package flyio

import (
	"errors"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/superfly/macaroon"
	"github.com/superfly/macaroon/resset"
)

func TestAccess(t *testing.T) {
	var noError error

	// orgid required
	assertError(t, resset.ErrResourceUnspecified, (&Access{}).Validate())
	assertError(t, resset.ErrResourceUnspecified, (&Access{
		OrgSlug: ptr("x"),
	}).Validate())
	assertError(t, noError, (&Access{
		DeprecatedOrgID: uptr(1),
	}).Validate())

	// org-level resources are mutually exclusive
	assertError(t, resset.ErrResourcesMutuallyExclusive, (&Access{
		DeprecatedOrgID: uptr(1),
		DeprecatedAppID: uptr(1),
		Feature:         ptr("x"),
	}).Validate())
	assertError(t, noError, (&Access{
		DeprecatedOrgID: uptr(1),
		DeprecatedAppID: uptr(1),
	}).Validate())
	assertError(t, noError, (&Access{
		DeprecatedOrgID: uptr(1),
		DeprecatedAppID: uptr(1),
	}).Validate())
	assertError(t, noError, (&Access{
		DeprecatedOrgID: uptr(1),
		Feature:         ptr("x"),
	}).Validate())

	// can't specify clusters without litefs-cloud feature
	assertError(t, resset.ErrResourceUnspecified, (&Access{
		DeprecatedOrgID: uptr(1),
		Cluster:         ptr("foo"),
	}).Validate())
	assertError(t, macaroon.ErrInvalidAccess, (&Access{
		DeprecatedOrgID: uptr(1),
		Feature:         ptr("x"),
		Cluster:         ptr("foo"),
	}).Validate())
	assert.NoError(t, (&Access{
		DeprecatedOrgID: uptr(1),
		Feature:         ptr(FeatureLFSC),
		Cluster:         ptr("foo"),
	}).Validate())

	// can't specify encoded app id without numeric
	assertError(t, resset.ErrResourceUnspecified, (&Access{
		DeprecatedOrgID: uptr(1),
		AppID:           ptr("x"),
	}).Validate())

	// can (should) specify numeric and encoded app id
	assertError(t, noError, (&Access{
		DeprecatedOrgID: uptr(1),
		AppID:           ptr("x"),
		DeprecatedAppID: uptr(1),
	}).Validate())
}

func assertError(tb testing.TB, expected, actual error) {
	tb.Helper()
	if expected == nil {
		assert.NoError(tb, actual)
	} else {
		assert.Error(tb, actual)
		assert.True(tb, errors.Is(actual, expected), "expected %v, got %v", expected, actual)
	}
}
