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
