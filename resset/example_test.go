package resset

import (
	"bytes"
	"fmt"
	"time"

	"github.com/superfly/macaroon"
)

const (
	// pick caveat type identifier from user-defined range
	CavWidgets = iota + macaroon.CavMinUserDefined
)

// implements macaroon.Caveat. Constrains access to widgets
type Widgets struct {
	Widgets ResourceSet[string] `json:"widgets"`
}

// register our Widgets caveat with the macaroons library so it's able to
// encode/decode them
func init() { macaroon.RegisterCaveatType(&Widgets{}) }

// implements macaroon.Caveat
func (c *Widgets) CaveatType() macaroon.CaveatType {
	return CavWidgets
}

// implements macaroon.Caveat
func (c *Widgets) Name() string {
	return "Widgets"
}

// implements macaroon.Caveat
func (c *Widgets) Prohibits(f macaroon.Access) error {
	wf, isWF := f.(*WidgetAccess)
	if !isWF {
		return macaroon.ErrInvalidAccess
	}

	return c.Widgets.Prohibits(wf.WidgetName, wf.Action)
}

// implements macaroon.Caveat
func (c *Widgets) IsAttestation() bool {
	return false
}

// implements macaroon.Access; describes an attempt to access a widget
type WidgetAccess struct {
	Action     Action
	WidgetName *string
}

// implements macaroon.Access
func (f *WidgetAccess) GetAction() Action {
	return f.Action
}

// implements macaroon.Access
func (f *WidgetAccess) Now() time.Time {
	return time.Now()
}

// implements macaroon.Access
func (f *WidgetAccess) Validate() error {
	return nil
}

const (
	// location identifies macaroons belonging to our widget factory
	widgetFactoryLocation = "https://widget-factory.example"
)

var (
	widgetFactoryKeyID = []byte("widget-factory-key-id")
	widgetFactoryKey   = macaroon.NewSigningKey()
)

func Example() {
	// create a new macaroon with no caveats
	userMacaroon, err := macaroon.New(
		widgetFactoryKeyID,
		widgetFactoryLocation,
		widgetFactoryKey,
	)
	if err != nil {
		panic(err)
	}

	// constrain the macaroon to accessing widget "foo" with any action or
	// reading widget "bar".
	err = userMacaroon.Add(&Widgets{ResourceSet[string]{
		"foo": ActionAll,
		"bar": ActionRead,
	}})
	if err != nil {
		panic(err)
	}

	// encode macaraoon in order to give it to the user
	encodedMacaroon, err := userMacaroon.Encode()
	if err != nil {
		panic(err)
	}

	// ...
	// some time later the user makes a request to our widget factory,
	// presenting us with the encoded macaroon
	// ...

	// decode the user's macaroon
	decoded, err := macaroon.Decode(encodedMacaroon)
	if err != nil {
		panic(err)
	}

	if !bytes.Equal(widgetFactoryKeyID, decoded.Nonce.KID) {
		panic("macaroon signed with wrong key")
	}

	// verify the signature on the macaroon
	verifiedCaveats, err := decoded.Verify(widgetFactoryKey, nil, nil)
	if err != nil {
		panic(err)
	}

	// validate the user's attempt to write to widget "foo"
	err = verifiedCaveats.Validate(&WidgetAccess{
		Action:     ActionWrite,
		WidgetName: ptr("foo"),
	})
	if err != nil {
		panic(err)
	}

	// Output: macaroon allows write access to widget "foo"
	fmt.Println(`macaroon allows write access to widget "foo"`)
}

func ptr[T any](v T) *T {
	return &v
}
