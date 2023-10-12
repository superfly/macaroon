<!-- Code generated by gomarkdoc. DO NOT EDIT -->

# Fly.io Macaroon Tokens

This is the extracted Macaroon token code we use for authorization inside of Fly.io. Because [flyctl](https://github.com/superfly/flyctl), our CLI, is open source, it can't fully exploit our tokens unless this library is open source as well. So it is.

We don't think you should use any of this code; it's shrink-wrapped around some peculiar details of our production network, and the data model is Fly-specific. But if it's an interesting to read, that's great too.

# macaroon

```go
import "github.com/superfly/macaroon"
```

Package macaroon defines Fly.io's Macaroon token format.

A [Macaroon](<https://storage.googleapis.com/pub-tools-public-publication-data/pdf/41892.pdf>) is a flexible bearer token based on the idea of "caveats". A caveat limits what a Macaroon can do. A blank Macaroon might represent an all\-access credential; a caveat layered onto that Macaroon might transform it into a read\-only credential; a further caveat might create a credential that can only read, and only to a particular file.

The basic laws of Macaroons:

- Anybody can add a caveat onto a Macaroon, even if they didn't originally issue it.
- A caveat can only further restrict a Macaroon's access; adding a caveat can't even increase access.
- Given a Macaroon with a set of caveats \(A, B, C\), it's cryptographically impossible to remove any caveat, to produce an \(A, B\) Macaroon or a \(B, C\).

An ordinary caveat is checked by looking at the request and the caveat and seeing if they match up. For instance, a Macaroon with an \`Operation=read\` caveat can be checked by looking to see if the request it accompanies is trying to write. Simple stuff.

A "third party \(3P\)" caveat works differently. 3P caveats demand that some other named system validate the request.

Users extract a little ticket from the 3P caveat and hands it to the third party, along with anything else the third party might want. That third party resolves the caveat by generating a "discharge Macaroon", which is a whole 'nother token, tied cryptographically to the original 3P caveat. The user then presents both the original Macaroon and the discharge Macaroon with their request.

For instance: most Fly.io Macaroons require a logged\-in user \(usually a member of a particular organization\). We express that with a 3P caveat pointing to our authentication endpoint. That endpoint checks to see who you're logged in as, and produces an appropriate discharge, which accompanies the original Macaroon and \(in effect\) attests to you being logged in.

### Cryptography

All the cryptography in Macaroons is symmetric; there are no public keys.

We use SHA256 as our hash, and HMAC\-SHA256 as our authenticator.

We use ChaCha20/Poly1305 as the AEAD for third\-party caveats.

### Fly Macaroon Format

Our Macaroons are simple structs encoded with [MessagePack](<https://msgpack.org/index.html>). We use a binary encoding both for performance and to to encode deterministically, for cryptography. MessagePack is extraordinarily simple and you can reason about this code as if simply used JSON.

A typical Fly.io request from a user will require multiple tokens; the original "root" token, which says what you're allowed to do, and tokens to validate 3P caveats \(usually at least an authentication token\).

To represent that bundle of tokens, we define a \`FlyV1\` HTTP \`Authorization\` header scheme, which is simply a comma\-separated set of Base64'd Macaroons.

### Internal Deployment

See the \`flyio\` package for more details.

### Basic Library Usage

- Create a token with [New](<#New>).

- Add caveats \("attenuating" it\) with [Macaroon.Add](<#Macaroon.Add>).

- Sign and encode the token with [Macaroon.Encode](<#Macaroon.Encode>).

- Decode a binary token with [Decode](<#Decode>).

- Verify the signatures on a token with [Macaroon.Verify](<#Macaroon.Verify>). Note that the whole token has not been checked at this point\!

- Check the caveats \(the result of [Macaroon.Verify](<#Macaroon.Verify>)\) with [CaveatSet.Validate](<#CaveatSet.Validate>).

## Index

- [Constants](<#constants>)
- [Variables](<#variables>)
- [func DischargeTicket\(ka EncryptionKey, location string, ticket \[\]byte\) \(\[\]Caveat, \*Macaroon, error\)](<#DischargeTicket>)
- [func FindPermissionAndDischargeTokens\(tokens \[\]\[\]byte, location string\) \(\[\]\*Macaroon, \[\]\[\]byte, \[\]\*Macaroon, \[\]\[\]byte, error\)](<#FindPermissionAndDischargeTokens>)
- [func GetCaveats\[T Caveat\]\(c \*CaveatSet\) \(ret \[\]T\)](<#GetCaveats>)
- [func IsAttestation\(c Caveat\) bool](<#IsAttestation>)
- [func Parse\(header string\) \(\[\]\[\]byte, error\)](<#Parse>)
- [func ParsePermissionAndDischargeTokens\(header string, location string\) \(\[\]byte, \[\]\[\]byte, error\)](<#ParsePermissionAndDischargeTokens>)
- [func RegisterCaveatJSONAlias\(typ CaveatType, alias string\)](<#RegisterCaveatJSONAlias>)
- [func RegisterCaveatType\(zeroValue Caveat\)](<#RegisterCaveatType>)
- [func ThirdPartyTicket\(encodedMacaroon \[\]byte, thirdPartyLocation string\) \(\[\]byte, error\)](<#ThirdPartyTicket>)
- [func ToAuthorizationHeader\(toks ...\[\]byte\) string](<#ToAuthorizationHeader>)
- [func Validate\[A Access\]\(cs \*CaveatSet, accesses ...A\) error](<#Validate>)
- [type Access](<#Access>)
- [type Attestation](<#Attestation>)
- [type BindToParentToken](<#BindToParentToken>)
  - [func \(c \*BindToParentToken\) CaveatType\(\) CaveatType](<#BindToParentToken.CaveatType>)
  - [func \(c \*BindToParentToken\) Name\(\) string](<#BindToParentToken.Name>)
  - [func \(c \*BindToParentToken\) Prohibits\(f Access\) error](<#BindToParentToken.Prohibits>)
- [type Caveat](<#Caveat>)
- [type Caveat3P](<#Caveat3P>)
  - [func \(c \*Caveat3P\) CaveatType\(\) CaveatType](<#Caveat3P.CaveatType>)
  - [func \(c \*Caveat3P\) Name\(\) string](<#Caveat3P.Name>)
  - [func \(c \*Caveat3P\) Prohibits\(f Access\) error](<#Caveat3P.Prohibits>)
- [type CaveatSet](<#CaveatSet>)
  - [func DecodeCaveats\(buf \[\]byte\) \(\*CaveatSet, error\)](<#DecodeCaveats>)
  - [func NewCaveatSet\(caveats ...Caveat\) \*CaveatSet](<#NewCaveatSet>)
  - [func \(c \*CaveatSet\) DecodeMsgpack\(dec \*msgpack.Decoder\) error](<#CaveatSet.DecodeMsgpack>)
  - [func \(c CaveatSet\) EncodeMsgpack\(enc \*msgpack.Encoder\) error](<#CaveatSet.EncodeMsgpack>)
  - [func \(c CaveatSet\) MarshalJSON\(\) \(\[\]byte, error\)](<#CaveatSet.MarshalJSON>)
  - [func \(c CaveatSet\) MarshalMsgpack\(\) \(\[\]byte, error\)](<#CaveatSet.MarshalMsgpack>)
  - [func \(c \*CaveatSet\) UnmarshalJSON\(b \[\]byte\) error](<#CaveatSet.UnmarshalJSON>)
  - [func \(c \*CaveatSet\) Validate\(accesses ...Access\) error](<#CaveatSet.Validate>)
- [type CaveatType](<#CaveatType>)
- [type EncryptionKey](<#EncryptionKey>)
  - [func NewEncryptionKey\(\) EncryptionKey](<#NewEncryptionKey>)
- [type Macaroon](<#Macaroon>)
  - [func Decode\(buf \[\]byte\) \(\*Macaroon, error\)](<#Decode>)
  - [func New\(kid \[\]byte, loc string, key SigningKey\) \(\*Macaroon, error\)](<#New>)
  - [func \(m \*Macaroon\) Add\(caveats ...Caveat\) error](<#Macaroon.Add>)
  - [func \(m \*Macaroon\) Add3P\(ka EncryptionKey, loc string, cs ...Caveat\) error](<#Macaroon.Add3P>)
  - [func \(m \*Macaroon\) Bind\(parent \[\]byte\) error](<#Macaroon.Bind>)
  - [func \(m \*Macaroon\) BindToParentMacaroon\(parent \*Macaroon\) error](<#Macaroon.BindToParentMacaroon>)
  - [func \(m \*Macaroon\) Encode\(\) \(\[\]byte, error\)](<#Macaroon.Encode>)
  - [func \(m \*Macaroon\) Expiration\(\) time.Time](<#Macaroon.Expiration>)
  - [func \(m \*Macaroon\) ThirdPartyTicket\(location string, existingDischarges ...\[\]byte\) \(\[\]byte, error\)](<#Macaroon.ThirdPartyTicket>)
  - [func \(m \*Macaroon\) ThirdPartyTickets\(existingDischarges ...\[\]byte\) \(map\[string\]\[\]byte, error\)](<#Macaroon.ThirdPartyTickets>)
  - [func \(m \*Macaroon\) Verify\(k SigningKey, discharges \[\]\[\]byte, trusted3Ps map\[string\]EncryptionKey\) \(\*CaveatSet, error\)](<#Macaroon.Verify>)
- [type Nonce](<#Nonce>)
  - [func DecodeNonce\(buf \[\]byte\) \(Nonce, error\)](<#DecodeNonce>)
  - [func \(n \*Nonce\) DecodeMsgpack\(d \*msgpack.Decoder\) error](<#Nonce.DecodeMsgpack>)
  - [func \(n \*Nonce\) EncodeMsgpack\(e \*msgpack.Encoder\) error](<#Nonce.EncodeMsgpack>)
  - [func \(n Nonce\) MustEncode\(\) \[\]byte](<#Nonce.MustEncode>)
  - [func \(n \*Nonce\) UUID\(\) uuid.UUID](<#Nonce.UUID>)
- [type SigningKey](<#SigningKey>)
  - [func NewSigningKey\(\) SigningKey](<#NewSigningKey>)
- [type ValidityWindow](<#ValidityWindow>)
  - [func \(c \*ValidityWindow\) CaveatType\(\) CaveatType](<#ValidityWindow.CaveatType>)
  - [func \(c \*ValidityWindow\) Name\(\) string](<#ValidityWindow.Name>)
  - [func \(c \*ValidityWindow\) Prohibits\(f Access\) error](<#ValidityWindow.Prohibits>)
- [type WrapperCaveat](<#WrapperCaveat>)


## Constants

<a name="EncryptionKeySize"></a>

```go
const (
    EncryptionKeySize = 32
)
```

## Variables

<a name="ErrUnrecognizedToken"></a>

```go
var (
    ErrUnrecognizedToken = errors.New("bad token")
    ErrUnauthorized      = errors.New("unauthorized")
    ErrInvalidAccess     = fmt.Errorf("%w: bad data for token verification", ErrUnauthorized)
    ErrBadCaveat         = fmt.Errorf("%w: bad caveat", ErrUnauthorized)
)
```

<a name="DischargeTicket"></a>
## func DischargeTicket

```go
func DischargeTicket(ka EncryptionKey, location string, ticket []byte) ([]Caveat, *Macaroon, error)
```

Decyrpts the ticket from the 3p caveat and prepares a discharge token. Returned caveats, if any, must be validated before issuing the discharge token to the user.

<a name="FindPermissionAndDischargeTokens"></a>
## func FindPermissionAndDischargeTokens

```go
func FindPermissionAndDischargeTokens(tokens [][]byte, location string) ([]*Macaroon, [][]byte, []*Macaroon, [][]byte, error)
```



<a name="GetCaveats"></a>
## func GetCaveats

```go
func GetCaveats[T Caveat](c *CaveatSet) (ret []T)
```

GetCaveats gets any caveats of type T, including those nested within IfPresent caveats.

<a name="IsAttestation"></a>
## func IsAttestation

```go
func IsAttestation(c Caveat) bool
```



<a name="Parse"></a>
## func Parse

```go
func Parse(header string) ([][]byte, error)
```

Parses an Authorization header into its constituent tokens.

<a name="ParsePermissionAndDischargeTokens"></a>
## func ParsePermissionAndDischargeTokens

```go
func ParsePermissionAndDischargeTokens(header string, location string) ([]byte, [][]byte, error)
```

Parse a string token and find the contained permission token for the given location.

<a name="RegisterCaveatJSONAlias"></a>
## func RegisterCaveatJSONAlias

```go
func RegisterCaveatJSONAlias(typ CaveatType, alias string)
```

Register an alternate name for this caveat type that will be recognized when decoding JSON.

<a name="RegisterCaveatType"></a>
## func RegisterCaveatType

```go
func RegisterCaveatType(zeroValue Caveat)
```

Register a caveat type for use with this library.

<a name="ThirdPartyTicket"></a>
## func ThirdPartyTicket

```go
func ThirdPartyTicket(encodedMacaroon []byte, thirdPartyLocation string) ([]byte, error)
```

Checks the macaroon for a third party caveat for the specified location. Returns the caveat's encrypted ticket, if found.

<a name="ToAuthorizationHeader"></a>
## func ToAuthorizationHeader

```go
func ToAuthorizationHeader(toks ...[]byte) string
```

ToAuthorizationHeader formats a collection of tokens as an HTTP Authorization header.

<a name="Validate"></a>
## func Validate

```go
func Validate[A Access](cs *CaveatSet, accesses ...A) error
```

Helper for validating concretely\-typed accesses.

<a name="Access"></a>
## type Access

Access represents the user's attempt to access some resource. Different caveats will require different contextual information.

```go
type Access interface {
    // The current time
    Now() time.Time

    // Callback for validating the structure
    Validate() error
}
```

<a name="Attestation"></a>
## type Attestation

Attestations make a positive assertion rather than constraining access to a resource. Most caveats are not attestations. Attestations may only be included in Proofs \(macaroons whose signature is finalized and cannot have more caveats appended by the user\).

```go
type Attestation interface {
    Caveat

    // Whether or not this caveat type is an attestation.
    IsAttestation() bool
}
```

<a name="BindToParentToken"></a>
## type BindToParentToken

BindToParentToken is used by discharge tokens to state that they may only be used to discharge 3P caveats for a specific root token or further attenuated versions of that token. This prevents a discharge token from being used with less attenuated versions of the specified token, effectively binding the discharge token to the root token. This caveat may appear multiple times to iteratively clamp down which versions of the root token the discharge token may be used with.

The parent token is identified by a prefix of the SHA256 digest of the token's signature.

```go
type BindToParentToken []byte
```

<a name="BindToParentToken.CaveatType"></a>
### func \(\*BindToParentToken\) CaveatType

```go
func (c *BindToParentToken) CaveatType() CaveatType
```



<a name="BindToParentToken.Name"></a>
### func \(\*BindToParentToken\) Name

```go
func (c *BindToParentToken) Name() string
```



<a name="BindToParentToken.Prohibits"></a>
### func \(\*BindToParentToken\) Prohibits

```go
func (c *BindToParentToken) Prohibits(f Access) error
```



<a name="Caveat"></a>
## type Caveat

Caveat is the interface implemented by all caveats.

```go
type Caveat interface {
    // The numeric caveat type identifier.
    CaveatType() CaveatType

    // The string name of the caveat. Used for JSON encoding.
    Name() string

    // Callback for checking if the authorization check is blocked by this
    // caveat. Implementors must take care to return appropriate error types,
    // as they have bearing on the evaluation of IfPresent caveats.
    // Specifically, returning ErrResourceUnspecified indicates that caveat
    // constrains access to a resource type that isn't specified by the Access.
    Prohibits(f Access) error
}
```

<a name="Caveat3P"></a>
## type Caveat3P

Caveat3P is a requirement that the token be presented along with a 3P discharge token.

```go
type Caveat3P struct {
    Location    string
    VerifierKey []byte // used by the initial issuer to verify discharge macaroon
    Ticket      []byte // used by the 3p service to construct discharge macaroon
    // contains filtered or unexported fields
}
```

<a name="Caveat3P.CaveatType"></a>
### func \(\*Caveat3P\) CaveatType

```go
func (c *Caveat3P) CaveatType() CaveatType
```



<a name="Caveat3P.Name"></a>
### func \(\*Caveat3P\) Name

```go
func (c *Caveat3P) Name() string
```



<a name="Caveat3P.Prohibits"></a>
### func \(\*Caveat3P\) Prohibits

```go
func (c *Caveat3P) Prohibits(f Access) error
```



<a name="CaveatSet"></a>
## type CaveatSet

CaveatSet is how a set of caveats is serailized/encoded.

```go
type CaveatSet struct {
    Caveats []Caveat
}
```

<a name="DecodeCaveats"></a>
### func DecodeCaveats

```go
func DecodeCaveats(buf []byte) (*CaveatSet, error)
```

Decodes a set of serialized caveats.

<a name="NewCaveatSet"></a>
### func NewCaveatSet

```go
func NewCaveatSet(caveats ...Caveat) *CaveatSet
```

Create a new CaveatSet comprised of the specified caveats.

<a name="CaveatSet.DecodeMsgpack"></a>
### func \(\*CaveatSet\) DecodeMsgpack

```go
func (c *CaveatSet) DecodeMsgpack(dec *msgpack.Decoder) error
```

Implements msgpack.CustomDecoder

<a name="CaveatSet.EncodeMsgpack"></a>
### func \(CaveatSet\) EncodeMsgpack

```go
func (c CaveatSet) EncodeMsgpack(enc *msgpack.Encoder) error
```

Implements msgpack.CustomEncoder

<a name="CaveatSet.MarshalJSON"></a>
### func \(CaveatSet\) MarshalJSON

```go
func (c CaveatSet) MarshalJSON() ([]byte, error)
```



<a name="CaveatSet.MarshalMsgpack"></a>
### func \(CaveatSet\) MarshalMsgpack

```go
func (c CaveatSet) MarshalMsgpack() ([]byte, error)
```

Implements msgpack.Marshaler

<a name="CaveatSet.UnmarshalJSON"></a>
### func \(\*CaveatSet\) UnmarshalJSON

```go
func (c *CaveatSet) UnmarshalJSON(b []byte) error
```



<a name="CaveatSet.Validate"></a>
### func \(\*CaveatSet\) Validate

```go
func (c *CaveatSet) Validate(accesses ...Access) error
```

Validates that the caveat set permits the specified accesses.

<a name="CaveatType"></a>
## type CaveatType

A numeric identifier for caveat types. Values less than CavMinUserRegisterable \(0x100000000\) are reserved for use by fly.io. Users may request a globally\-recognized caveat type via pull requests to this repository. Implementations that don't need to integrate with fly.io itself can pick from the user\-defined range \(\>0x1000000000000\).

```go
type CaveatType uint64
```

<a name="CavFlyioOrganization"></a>

```go
const (
    CavFlyioOrganization CaveatType = iota

    CavFlyioVolumes
    CavFlyioApps
    CavValidityWindow
    CavFlyioFeatureSet
    CavFlyioMutations
    CavFlyioMachines
    CavFlyioConfineUser
    CavFlyioConfineOrganization
    CavFlyioIsUser
    Cav3P
    CavBindToParentToken
    CavIfPresent
    CavFlyioMachineFeatureSet
    CavFlyioFromMachineSource
    CavFlyioClusters

    // Globally-recognized user-registerable caveat types may be requested via
    // pull requests to this repository. Add a meaningful name of the caveat
    // type (e.g. CavAcmeCorpWidgetID) on the line prior to
    // CavMaxUserRegisterable.
    CavMinUserRegisterable = 1 << 32
    CavMaxUserRegisterable = 1<<48 - 1

    CavMinUserDefined = 1 << 48
    CavMaxUserDefined = 1<<64 - 2
    CavUnregistered   = 1<<64 - 1
)
```

<a name="EncryptionKey"></a>
## type EncryptionKey



```go
type EncryptionKey []byte
```

<a name="NewEncryptionKey"></a>
### func NewEncryptionKey

```go
func NewEncryptionKey() EncryptionKey
```



<a name="Macaroon"></a>
## type Macaroon

Macaroon is the fully\-functioning internal representation of a token \-\-\- you've got a Macaroon either because you're constructing a new token yourself, or because you've parsed a token from the wire.

Some fields in these structures are JSON\-encoded because we use a JSON representation of Macaroons in IPC with our Rails API, which doesn't have a good FFI to talk to Go.

```go
type Macaroon struct {
    Nonce    Nonce  `json:"-"`
    Location string `json:"location"`

    // Retrieve caveats from a Macaroon you don't trust
    // by calling [Macaroon.Verify], not by poking into
    // the struct.
    UnsafeCaveats CaveatSet `json:"caveats"`
    Tail          []byte    `json:"-"`
    // contains filtered or unexported fields
}
```

<a name="Decode"></a>
### func Decode

```go
func Decode(buf []byte) (*Macaroon, error)
```

Decode parses a token off the wire; to get usable caveats. There are two things you can do with a freshly\-decoded Macaroon:

- You can verify the signature and recover the caveats with [Macaroon.Verify](<#Macaroon.Verify>)

- You can add additional caveats to the Macaroon with [Macaroon.Add](<#Macaroon.Add>), and then call [Macaroon.Encode](<#Macaroon.Encode>) to re\-encode it \(this is called "attenuation", and it's what you'd do to take a read\-write token and make it a read\-only token, for instance.

Note that calling [Macaroon.Verify](<#Macaroon.Verify>) requires a secret key, but [Macaroon.Add](<#Macaroon.Add>) and [Macaroon.Encode](<#Macaroon.Encode>) does not. That's a Macaroon magic power.

<a name="New"></a>
### func New

```go
func New(kid []byte, loc string, key SigningKey) (*Macaroon, error)
```

New creates a new token given a key\-id string \(which can be any opaque string and doesn't need to be cryptographically random or anything; the key\-id is how you're going to relate the token back to a key you've saved somewhere; it's probably a database rowid somehow\) and a location, which is ordinarily a URL. The key is the signing secret.

<a name="Macaroon.Add"></a>
### func \(\*Macaroon\) Add

```go
func (m *Macaroon) Add(caveats ...Caveat) error
```

Add adds a caveat to a Macaroon, adjusting the tail signature in the process. This is how you'd "attenuate" a token, taking a read\-write token and turning it into a read\-only token, for instance.

<a name="Macaroon.Add3P"></a>
### func \(\*Macaroon\) Add3P

```go
func (m *Macaroon) Add3P(ka EncryptionKey, loc string, cs ...Caveat) error
```

Add3P adds a third\-party caveat to a Macaroon. A third\-party caveat is checked not by evaluating what it means, but instead by looking for a "discharge token" \-\-\- a second token sent along with the token that says "some other service verified that the claims corresponding to this caveat are true".

Add3P needs a key, which binds this token to the service that validates it. Every authentication caveat, for instance, shares an authentication key; the key connects the root service to the authentication service.

Add3P takes a location, which is used to figure out which keys to use to check which caveats. The location is normally a URL. The authentication service has an authentication location URL.

<a name="Macaroon.Bind"></a>
### func \(\*Macaroon\) Bind

```go
func (m *Macaroon) Bind(parent []byte) error
```

Bind cryptographically binds a discharge token to the "parent" token it's meant to accompany. This is a convenience method that takes a raw unparsed parent token as an argument.

Discharge tokens are generated by third\-party services \(like our authentication service, or your Slack bot\) to satisfy a third\-party caveat. Users present both the original and the discharge token when they make requests. Discharge tokens must be bound when they're sent; doing so prevents Discharge tokens from being replayed in some other context.

<a name="Macaroon.BindToParentMacaroon"></a>
### func \(\*Macaroon\) BindToParentMacaroon

```go
func (m *Macaroon) BindToParentMacaroon(parent *Macaroon) error
```

See [Macaroon.Bind](<#Macaroon.Bind>); this is that function, but it takes a parsed Macaroon.

<a name="Macaroon.Encode"></a>
### func \(\*Macaroon\) Encode

```go
func (m *Macaroon) Encode() ([]byte, error)
```

Encode encodes a Macaroon to bytes after creating it or decoding it and adding more caveats.

<a name="Macaroon.Expiration"></a>
### func \(\*Macaroon\) Expiration

```go
func (m *Macaroon) Expiration() time.Time
```

Expiration calculates when this macaroon will expire

<a name="Macaroon.ThirdPartyTicket"></a>
### func \(\*Macaroon\) ThirdPartyTicket

```go
func (m *Macaroon) ThirdPartyTicket(location string, existingDischarges ...[]byte) ([]byte, error)
```

ThirdPartyTicket returns the ticket \(see \[Macaron.ThirdPartyTickets\]\) associated with a URL location, if possible.

<a name="Macaroon.ThirdPartyTickets"></a>
### func \(\*Macaroon\) ThirdPartyTickets

```go
func (m *Macaroon) ThirdPartyTickets(existingDischarges ...[]byte) (map[string][]byte, error)
```

ThirdPartyTickets extracts the encrypted tickets from a token's third party caveats.

The ticket of a third\-party caveat is a little ticket embedded in the caveat that is readable by the third\-party service for which it's intended. That service uses the ticket to generate a compatible discharge token to satisfy the caveat.

Macaroon services of all types are identified by their "location", which in our scheme is always a URL. ThirdPartyTickets returns a map of location to ticket. In a perfect world, you could iterate over this map hitting each URL and passing it the associated ticket, collecting all the discharge tokens you need for the request \(it is never that simple, though\).

Already\-discharged caveats are excluded from the results.

<a name="Macaroon.Verify"></a>
### func \(\*Macaroon\) Verify

```go
func (m *Macaroon) Verify(k SigningKey, discharges [][]byte, trusted3Ps map[string]EncryptionKey) (*CaveatSet, error)
```

Verify checks the signature on a \[Macaroon.Decode\] 'ed Macaroon and returns the the set of caveats that require validation against the user's request.

Verify is the primary way you recover caveats from a Macaroon. Note that the caveats returned are the semantically meaningful subset of caveats that might need to be checked against the request. Third\-party caveats are validated implicitly by checking sgnatures, and aren't returned by Verify.

\(A fun wrinkle, though: a 3P discharge token can add additional ordinary caveats to a token; you can, for instance, discharge our authentication token with a token that says "yes, this person is logged in as bob@victim.com, but only allow this request to perform reads, not writes"\). Those added ordinary caveats WILL be returned from Verify.

<a name="Nonce"></a>
## type Nonce

A Nonce in cryptography is a random number that is only used once. A Nonce on a [Macaroon](<#Macaroon>) is a blob of data that encodes, most impotantly, the "key ID" \(KID\) of the token; the KID is an opaque value that you, the library caller, provide when you create a token; it's the database key you use to tie the Macaroon to your database.

```go
type Nonce struct {
    // contains filtered or unexported fields
}
```

<a name="DecodeNonce"></a>
### func DecodeNonce

```go
func DecodeNonce(buf []byte) (Nonce, error)
```

DecodeNonce parses just the [Nonce](<#Nonce>) from an encoded [Macaroon](<#Macaroon>). You'd want to do this, for instance, to look metadata up by the keyid of the [Macaroon](<#Macaroon>), which is encoded in the [Nonce](<#Nonce>).

<a name="Nonce.DecodeMsgpack"></a>
### func \(\*Nonce\) DecodeMsgpack

```go
func (n *Nonce) DecodeMsgpack(d *msgpack.Decoder) error
```

DecodeMsgpack implements \[msgpack.CustomDecoder\]

<a name="Nonce.EncodeMsgpack"></a>
### func \(\*Nonce\) EncodeMsgpack

```go
func (n *Nonce) EncodeMsgpack(e *msgpack.Encoder) error
```

EncodeMsgpack implements \[msgpack.CustomDecoder\]

<a name="Nonce.MustEncode"></a>
### func \(Nonce\) MustEncode

```go
func (n Nonce) MustEncode() []byte
```



<a name="Nonce.UUID"></a>
### func \(\*Nonce\) UUID

```go
func (n *Nonce) UUID() uuid.UUID
```

UUID is a simple globally unique identifier string for a nonce.

<a name="SigningKey"></a>
## type SigningKey



```go
type SigningKey []byte
```

<a name="NewSigningKey"></a>
### func NewSigningKey

```go
func NewSigningKey() SigningKey
```



<a name="ValidityWindow"></a>
## type ValidityWindow

ValidityWindow establishes the window of time the token is valid for.

```go
type ValidityWindow struct {
    NotBefore int64 `json:"not_before"`
    NotAfter  int64 `json:"not_after"`
}
```

<a name="ValidityWindow.CaveatType"></a>
### func \(\*ValidityWindow\) CaveatType

```go
func (c *ValidityWindow) CaveatType() CaveatType
```



<a name="ValidityWindow.Name"></a>
### func \(\*ValidityWindow\) Name

```go
func (c *ValidityWindow) Name() string
```



<a name="ValidityWindow.Prohibits"></a>
### func \(\*ValidityWindow\) Prohibits

```go
func (c *ValidityWindow) Prohibits(f Access) error
```



<a name="WrapperCaveat"></a>
## type WrapperCaveat

WrapperCaveat should be implemented by caveats that wrap other caveats \(eg. resset.IfPresent\).

```go
type WrapperCaveat interface {
    Unwrap() *CaveatSet
}
```

Generated by [gomarkdoc](<https://github.com/princjef/gomarkdoc>)
