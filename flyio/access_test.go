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
	assertError(t, noError, (&Access{
		OrgSlug: ptr("x"),
	}).Validate())
	assertError(t, noError, (&Access{
		DeprecatedOrgID: uptr(1),
	}).Validate())

	// org-level resources are mutually exclusive
	assertError(t, macaroon.ErrResourcesMutuallyExclusive, (&Access{
		OrgSlug: ptr("x"),
		AppID:   ptr("x"),
		Feature: ptr("x"),
		Cluster: ptr("x"),
	}).Validate())
	assertError(t, macaroon.ErrResourcesMutuallyExclusive, (&Access{
		OrgSlug: ptr("x"),
		Feature: ptr("x"),
		Cluster: ptr("x"),
	}).Validate())
	assertError(t, macaroon.ErrResourcesMutuallyExclusive, (&Access{
		OrgSlug: ptr("x"),
		AppID:   ptr("x"),
		Cluster: ptr("x"),
	}).Validate())
	assertError(t, macaroon.ErrResourcesMutuallyExclusive, (&Access{
		OrgSlug:         ptr("x"),
		DeprecatedAppID: uptr(1),
		Feature:         ptr("x"),
	}).Validate())
	assertError(t, macaroon.ErrResourcesMutuallyExclusive, (&Access{
		OrgSlug:         ptr("x"),
		DeprecatedAppID: uptr(1),
		Cluster:         ptr("x"),
	}).Validate())
	assertError(t, macaroon.ErrResourcesMutuallyExclusive, (&Access{
		OrgSlug: ptr("x"),
		AppID:   ptr("x"),
		Feature: ptr("x"),
	}).Validate())
	assertError(t, noError, (&Access{
		OrgSlug: ptr("x"),
		AppID:   ptr("x"),
	}).Validate())
	assertError(t, noError, (&Access{
		OrgSlug:         ptr("x"),
		DeprecatedAppID: uptr(1),
	}).Validate())
	assertError(t, noError, (&Access{
		OrgSlug: ptr("x"),
		Feature: ptr("x"),
	}).Validate())
	assertError(t, noError, (&Access{
		OrgSlug: ptr("x"),
		Cluster: ptr("x"),
	}).Validate())

	// can (should) specify numeric and encoded app id
	assertError(t, noError, (&Access{
		OrgSlug:         ptr("x"),
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

func ptr[T any](v T) *T {
	return &v
}

func uptr(v uint64) *uint64 {
	return ptr(v)
}
