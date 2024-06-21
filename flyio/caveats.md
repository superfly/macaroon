
# Macaroons and Caveats at Fly

This document covers the general mechanisms of Macaroons as they are used at
Fly to do access control. It does not cover the cryptographic constructs.

Macaroons are tokens. They are define in https://github.com/superfly/macaroon.
At fly we pass them to services in `Authorization: Bearer <token>` HTTP headers.
Several tokens can be passed in a single header, separated by commas. Access
control is allowed if any one of the bearer tokens allows access.

A Macaroon is extensible. Users that have a token can construct new tokens
from them by adding Caveats. A Caveat is a restriction on the token's use.
A token with no Caveats is all powerful, and tokens with Caveats wittle away
at that power. Fly always issues tokens with an Org caveat which limits the
token to operate on a single organization. A user in many organizations may
pass in many tokens to operate across many organizations.

Macaroons support "third party" caveats. These are special in a few ways.
Third party caveats are "discharged" by an accompanying third party discharge
token. A third party caveat in a token fails if there is no accompanying third party
discharge passed along with the token. Fly only honors third party discharge tokens
issued by certain trusted third party issuers. These are:
- https://api.fly.io/aaa/v1
- https://auth.fly.io

Third party discharge tokens are also special in that we allow them to carry
attestations, and that they must be "finalized".  These attestations are used
to state a user's identity, such as the Fly user ID, or an SSO identity.
A finalized token cannot be extended.

## Access Control

Tokens grant access and are logically a predicate on access requests.
When evaluating if an operation can be performed, Fly services build up
an access request and evaluate it against the bearer tokens. The access
control predicate returns an error explaining an access control failure if
access is not allowed. It returns no error if access is allowed.

Fly uses the `flyio.Access` structure to represent access requests:

```
type Access struct {
        Action         resset.Action `json:"action,omitempty"`
        OrgID          *uint64       `json:"orgid,omitempty"`
        AppID          *uint64       `json:"appid,omitempty"`
        Feature        *string       `json:"feature,omitempty"`
        Volume         *string       `json:"volume,omitempty"`
        Machine        *string       `json:"machine,omitempty"`
        MachineFeature *string       `json:"machine_feature,omitempty"`
        Mutation       *string       `json:"mutation,omitempty"`
        SourceMachine  *string       `json:"sourceMachine,omitempty"`
        Cluster        *string       `json:"cluster,omitempty"`
        Command        []string      `json:"command,omitempty"`
}
```

The `Action` field encodes a set of actions requested: Read, Write, Create, Delete, or Control, encoded
as a string "rwcdC". The special encoding "*" denotes the set of all possible actions.

The other fields are optional fields, and denote what is being operated on.

## Bearer Token List

A bearer token list is a comma-seperated list of Macaroons provided in
the `Authorization: Bearer <tokens>` HTTP header. The list of tokens allows an access
if any of its tokens allows the access.

# Macaroon

A Macaroon contains a list of Caveats (a Caveat Set). A Macaroon allows an a access if all
of its Caveats Set allows an access. A Caveat Set allows an access if all of its
Caveats allow an action.

## Caveats

A Caveat is a restriction on access control. It is a predicate on an access
request. Some Caveats are special in that they can fail because they are
not relevant to the access being requested. In the source code this is
represented with the `ErrResourceUnspecified` access failure.  This failure
is just another access control failure in most situations. However, there is
a special `IfPresent` Caveat which treats these specific failures differently
than other failures. More on this later.

Caveats have a JSON representation, which is used by the `flyctl` tool
when rendering tokens (`flyctl tokens debug -t <token>`) or when attenuating
tokens (`flyctl tokens attenuate -f caveats.json`):

```
    {
       "type": "caveat-type",
       "body": caveat-body
    }
```

### Third Party Caveat

A third party caveat allows an access if the caveat is for a trusted third
party, and there is a discharge token for that third party in the bearer token list,
and if all of the caveats in the third party bearer token allow the access.
Third party discharge tokens must be finalized. This prevents them from being
extended. They may also carry attestations about a user's identity. A normal
Macaroon with an attestation in it is considered an error and does not allow access.

Action Caveats are always relevant (never return `ErrResourceUnspecified`).

### Action Caveat

An `Action` can be used as a Caveat. 
It encodes a set of actions requested: Read, Write, Create, Delete, or Control, encoded
as a string "rwcdC". The special encoding "*" denotes the set of all possible actions.
The Caveat allows an access if the requested action is a subset of the Caveat's actions.

Action Caveats are always relevant (never return `ErrResourceUnspecified`).
They are encoded in JSON as:

```
  {
    "type": "Action",
    "body": "rw"
  },
```

### Organization Caveat

The Organization Caveat specifies which actions are allowed in a single organization.
It allows an access request if the request is for the same organization and the
requested actions are a subset of the Caveat's actions.

Organization Caveats are not relevant (return `ErrResourceUnspecified`) if the
access request does not specify an organization.

There are several Caveats that allow access to a set of resources. These Caveats 
define a set of allowed actions for a set of resource identifiers. The App Org Caveat
is the first of these. 

```
  {
    "type": "Organization",
    "body": {
      "id": 9876,
      "mask": "w"
    }
  },
```

### Apps Caveat and Resource Sets

The Apps Caveat is the first of many "Resource Set" Caveats. This Caveat specifies a 
set of application IDs, and for each a set of actions allowed for that application.
The Caveat allows an access if the access request specifies an application ID in the
Caveat, and the requested action is a subset of the actions allowed for that application ID.

Apps Caveats are not relevant (return `ErrResourceUnspecified`) if the
access request does not specify an application.

```
  {
    "type": "Apps",
    "body": {
      "apps": {
        "1234": "w",
        "456": "rwcdC"
      }
    }
  },
```

Apps Caveats, and other Resource Set Caveats, can refer to all applications (all resources
in a set) by using the zero-valued key for an application ID, and no other application IDs:

```
  {
    "type": "Apps",
    "body": {
      "apps": {
        "0": "w"
      }
    }
  },
```


### Other Resource Set Caveats

There are other Resource Set Caveats. Unlike  the Apps Caveat, they use a string for the resource
ID instead of a number, so the zero-valued key used as a wildcard must be the empty string instead
of "0".  Other than that their behavior is very similar.  They allow an access if the resource
being requested is in the caveat, and if the access being requested is a subset of the access
allowed for that resource.  They are not relevant (return `ErrResourceUnspecified`) if the
access request does not specify the corresponding resource.

```
  {
    "type": "Volumes",
    "body": {
      "volumes": {
        "volid": "w"
      }
    }
  },
```

```
  {
    "type": "Machines",
    "body": {
      "machines": {
        "machid1": "w",
        "machid2": "w"
      }
    }
  },
```


```
  {
    "type": "MachineFeatureSet",
    "body": {
      "features": {
        "feat1": "w"
      }
    }
  },
```

```
  {
    "type": "FeatureSet",
    "body": {
      "features": {
        "feat1": "w"
      }
    }
  },
```

```
  {
    "type": "Clusters",
    "body": {
      "clusters": {
        "clust1": "w"
      }
    }
  },
```

### IfPresent Caveat

The IfPresent Caveat is a little bit different than other Caveats. It has an "if-then" part
and an "else" part. The "if-then" part contains a list of Caveats. Access is allowed if
all of the Caveats in the "if-then" part allow the access.  However, if all of the Caveats
in the "if-then" part are not relevant (they all return `ErrResourceUnspecified`), then
then instead the access is allowed if the requested action is a subset of the actions in
the "else" clause. This is the only Caveat that behaves differently when some Caveats
indicate that they are not relevant.

Note: if ANY of the IfPresent Caveat's constituents are relevant, then ALL of the Caveats
must allow the access.

```
  {
    "type": "IfPresent",
    "body": {
      "ifs": [
        {
          "type": "Apps",
          "body": {
            "apps": {
              "1234": "w"
            }
          }
        }
      ],
      "else": "r"
    }
  }
```

### Mutations Caveat

The Mutations Caveat restricts access to certain Mutations in the GraphQL API.
An access request is allowed if it specifies a mutation that is one of the mutations
listed in the Caveat.

Mutation Caveats are not relevant (return `ErrResourceUnspecified`) if the
access request does not specify a mutation.

```
  {
    "type": "Mutations",
    "body": {
      "mutations": [
        "mutation1",
        "mutation2"
      ]
    }
  },
```

### IsUser Caveat

Not sure. To quote: `IsUser is mostyly metadata and plays no role in access validation.`

It is always relevant, but never returns failure.

XXX I think some code searches for this caveat and treats it specially?

```
  {
    "type": "IsUser",
    "body": {
      "uint64": 1234
    }
  },
```


### NoAdminFeatures Caveat

NoAdminFeatures is a shorthand for specifying that the token isn't allowed to access admin-only features.
The Caveat carries no additional information.
It restricts access requests to specific features:

```
    FeatureWireGuard       = "wg"
    FeatureDomains         = "domain"
    FeatureSites           = "site"
    FeatureRemoteBuilders  = "builder"
    FeatureAddOns          = "addon"                       
    FeatureChecks          = "checks"
    FeatureLFSC            = "litefs-cloud"                
    FeatureMembership      = "membership"
    FeatureBilling         = "billing"
    FeatureDeletion        = "deletion"
    FeatureDocumentSigning = "document_signing"
    FeatureAuthentication  = "authentication"

    MemberFeatures = map[string]resset.Action{
        FeatureWireGuard:      resset.ActionAll,
        FeatureDomains:        resset.ActionAll,
        FeatureSites:          resset.ActionAll,
        FeatureRemoteBuilders: resset.ActionAll,
        FeatureAddOns:         resset.ActionAll,
        FeatureChecks:         resset.ActionAll,
        FeatureLFSC:           resset.ActionAll,
    
        FeatureMembership:     resset.ActionRead,
        FeatureBilling:        resset.ActionRead,
        FeatureAuthentication: resset.ActionRead,
            
        FeatureDeletion:        resset.ActionNone,
        FeatureDocumentSigning: resset.ActionNone,
    }   
```

If a requested feature is not in the `MemberFeatures` table access is not allowed.
If it is in the list, access is allowed if the requested action is a subset of
the actions in the table for the feature.

NoAdminFeatures Caveats are not relevant (return `ErrResourceUnspecified`) if the
access request does not specify a feature.

```
  {
    "type": "NoAdminFeatures",
    "body": {}
  },
```

### Commands Caveat

The Commands Caveat provides a restriction on which commands may be executed on a machine.
The Caveat contains a list of allowed commands. Each command is specified as an argument
vector, starting with the command name, and a flag specifying if an exact match is required.
The Commands Caveat allows an access request if it specifies a command, and the command matches
one of the commands in the Caveat.  The Command must exactly match a command vector if the
"exact" flag in the Caveat command is true. If the "exact" flag is not present or false, then
the requested command matches if the Caveat's command vector is a prefix of the requested command.
For example "ls -l /tmp" is allowed if the Caveat contains `"ls -l"` with the "exact" flag set to false.

Command Caveats are not relevant (return `ErrResourceUnspecified`) if the
access request does not specify a command.

```
{
    "type": "Commands",
    "body": [
      {
        "args": [
          "uptime"
        ],
        "exact": true
      },
      {
        "args": [
          "ls",
          "-l"
        ]
      }
    ]
  }
```
