# Integral Principles of the Structural Dynamics of Macaroons

## Describe a Fly Macaroon In The Fewest Words Possible

A Macaroon is an HMAC-authenticated access token. Fly Macaroons are encoded 
in [MsgPack](https://msgpack.org/index.html), which is a kind of binary JSON. Macaroons are like other kinds of access tokens, with these quirks:

* They're cryptographically secured using a minimal, non-negotiable set of
  primitives: HMAC and an AEAD cipher. There are no crypto parameters to set
  or verify.
  
* They're rigidly structured: every Macaroon is a set of restrictions on 
  what its holder can do. These are called caveats. All caveats 
  must approve an action (or "clear") for the token to authorize that action. 
  
* Anybody can take a Macaroon and add additional caveats to it before
  saving it or passing it on to someone else. This is called "attenuation". 
  Attenuating a token can't possibly give it more powers --- once added,
  caveats can't be removed (a clever chaining HMAC construction guarantees
  this), and all caveats must clear.
  
* A special kind of "third party" (3P) caveat encodes whether some other,
  possibly unrelated service needs to authorizes a request. That service needs 
  to understand Macaroons but doesn't need to be able to talk to Fly.io. 
  Fly.io doesn't need to know about the services. Some simple cryptography
  makes this work.
  
There's more to say but it'll all just confuse you until you get more context.

## A Brief Essay On The Semantics Of Checking Macaroons

A Macaroon accompanies a request that attempts an action. The Macaroon determines whether the action is authorized. There are two parts to this determination:

<dl>
  <dt>Verification</dt>
  <dd>... means checking the cryptographic authenticator on the Macaroon to ensure that the bytes in the token weren't tampered with (in particular: that no caveat added to the Macaroon was later removed).</dd>
  <dt>Clearing</dt>
  <dd>... means evaluating the contents of each caveat in the Macaroon to see if it forbids the requested action.</dd>
</dl>

Obviously, you need to do both things: without verification, you can simply mint a Macaroon that says you're allowed to do anything. Without clearing, the contents of the Macaroon don't matter. 

## The Fly.io Macaroon Data Model

The first thing to understand is that a Macaroon with no caveats at all would authorize any action, on anybody's account. It would be a superuser token. We won't generate tokens like this, and our Macaroon checking code will freak out if it sees one.

Instead, we require every Macaroon to begin with a caveat locking the token to a particular organization:

```go
type Organization struct {
	ID   uint64        `json:"id"`
	Mask resset.Action `json:"mask"`
}
```

We'll use a loose shorthand to talk about caveats. For example, if you've been given the most powerful Macaroon we'll issue for organization `4721`, it'll start with a caveat `(org=4721, mask=*)`. "Mask" is roughly a Unix file style permission mask; for now, think `rwx`.

The Macaroon we just described is much too powerful to hand out casually. The point of Macaroons is to scope access down. We support a variety of caveats
to do that:

* `Apps` locks a token down to a specific set of applications, identified by
  their app IDs. Like most of our caveats, each app has a Mask associated with 
  it.
  
* `Machines` locks a token down to a specific set of machines, identified 
  by their machine ID, the same way an `Apps` token does for apps.
  
* `Volumes`, same deal.

* `FeatureSet` and `Mutations` are escape hatches that identify bundles 
  of features by name (or by GraphQL mutation).
  
* `ValidityWindow` sets expiry for a token.

Note that you can take the token `(org=4721, mask=*)` and layer onto it
a caveat like `(app=8910, mask=*)`, _even if app 8910 isn't in org `4721`_. That's fine! Every caveat must clear, so if you tried to use that token to access app 8910, the Organization caveat would reject the action, regardless of what the App caveat said.

We currently recognize the following access mask bits:

* `r`: Read

* `w`: Write

* `c`: Create

* `d`: Delete

* `C`: Control

The first four are obvious, the last (`Control`) allows bearers to start
and stop machines (think of it as permission to "write" to the current "state"
of the Machine).

One of the basic things you'd do with a Macaroon is to change the access masks of previous caveats. For instance, this might be a common pattern:

```
   (org=4721, mask=*)
   (org=4721, mask=r)
```

This is us taking the administrator-level org token we started with and adding a new caveat that locks us down to read operations, to create a read-only token. 

You could further attenuate:

```
   (org=4721, mask=*)
   (org=4721, mask=r)
   ((app=123, mask=*), (app=345, mask=*))
```

Now we have a read-only token that only works for two apps in our organization; if our org has an app `456`, this token can't be used to access it. Meanwhile, what actions does this token allow us to take on app `123`? That's right: we can do read operations and nothing else. Even though the app caveat has `mask=*`, all the caveats have to check out, and the `(org=4721, mask=r)` caveat will reject writes to apps. 

This is a rigid model and it makes expressing some kinds of things tricky. It can result in situations where you might end up needing to hold on to more than one token to do all the things you need to do.

So why adopt this model? Because it makes tokens easy to reason about, once you have one and need to check it.

## The Fly Macaroon Security Model

A design goal we had with these tokens: it should be possible to generate a token for, say, a contractor, and email it to them, with plain-old-email, and not lose security.

_Don't actually email these tokens, but keep reading_.

Like other access tokens, Fly Macaroons are bearer credentials. At
the same time, stealing one from the mail shouldn't really cost us
much security. How does this work?

In addition to the Organization caveat, every Fly Macaroon we issue has a _third party (3P) caveat_ pointing to our authentication system. So a "real" admin token would look like this:

```
    (org=4721, mask=*)
    (third-party https://api.fly.io/aaa/v1 org=4721)
    (validity-window 3 months)
```

What that third-party caveat says is: to do something to org `4721`, 
present this token, and also another token, a "3P discharge token",
issued from https://api.fly.io/aaa/v1, that satisfies `org=4721`.

What this means is that the Macaroon above, which we'd call a "root Macaroon", can't do anything by itself. It's only useful in combination with a second Macaroon, the "authentication Macaroon", that proves you're logged in (in this case, to an account with access to org `4721`). 

To get that authentication Macaroon, you need a root Macaroon, and a Fly.io login to an account that has the right access to an organization. If an attacker steals your root Macaroon from the mail, and they can get the matching authorization Macaroon, they probably already had the access they needed.

Our library code hides the flow, but the dance of actually using a Fly Macaroon is:

1. Get the root Macaroon, which determines what it is you're allowed 
   to do.
   
2. Find the 3P auth caveat in that Macaroon, and present it
   (more on this later) to the https://api.fly.io/aaa service to obtain
   an auth discharge Macaroon. Now you have two Macaroons.
   
3. Present both tokens to our API to actually complete an action.

Some basic notes on the low-level security of these tokens:

* The root tokens are protected by HMAC-SHA256. Every organization has its
  own key material; there is no one secret you could steal that would let
  you mint arbitrary Macaroons.
  
* 3P discharge Macaroons are protected by ChaCha20/Poly1305. A 
  key is shared between `fly.io/aaa` and the rest of our API.
  
* The secrets needed to verify a Macaroon signature exist only on isolated
  hardware in our production network (in the sense that no customer workloads
  can run there). We run a [LiteFS](https://github.com/superfly/litefs)-backed 
  cluster of Macaroon signature verifiers (we call them `tkdb`s) around the    
  world.
  
## An Aside About Third Party Authentication Caveats

As you'll see later, 3P caveats involve a lot of mechanism. We didn't necessarily need all that mechanism to authenticate tokens. We could have instead come up with an `(authenticated-as uid=*, org=4721)` caveat. This caveat would clear if the request was submitted by someone logged into the system, which we'd verify by checking their standard OAuth token.

Why didn't we do this? Because our standard OAuth tokens are way too powerful. They're like the `(org=4721, mask=*)` Macaroon all by themselves. The whole point is to get rid of them. 

We still didn't need to use 3P caveats to accomplish this; we could design and issue a new set of OAuth tokens that only work with Macaroons, or some API key that expresses the same thing. But then we'd have to build those services, and while they'd probably be less mechanism than 3P caveats, we need 3P caveats for other things anyways, so it'd be a net complexity liability for us.

## Using Fly Macaroons

The function `ToAuthorizationHeader` in this library formats a bundle
of Macaroon tokens (usually: the "root" Macaroon and accompanying authentication discharge token) into the body of an `Authorization` HTTP
header. Those headers look like this:

```
    Authorization: FlyV1 fm2_Zm9vCg==,fm2_YmFyCg==
```

(Except way longer).

Each Macaroon is MsgPack-encoded, then base64'd, then has `fm2_` 
prepended so it's easy to grep for them, then joined with commas.

Both our [GraphQL API](https://api.fly.io/graphql) and our 
[Fly Machines API](https://fly.io/docs/machines/working-with-machines/) honor this `Authorization` header. 

You can theoretically send an arbitrary bundle of Macaroon tokens in our Authorization heder, and let the API figure out which one matches.

## Macaroon Attenuation

One of the big features of these tokens is that you can take them and
further restrict them, for instance by turning a read-write token into 
a read-only token. You can do this on your own, without talking to our
servers, and without having any kind of magic key. It's a pretty neat
trick. You could give a contractor a read-only token for a specific app,
and they in turn could take that token and slap a 12 hour expiry on it,
discarding the original one, to minimize hazmat. 

The most obvious ways to use this feature:

1. Start with an `(org=4721, mask=*)` token, and attenuate with 
   `(app=555, mask=*)` to make an app-specific token; give that token
   to the developers of that particular app.
   
2. Start with an `(org=4721, mask=*)` token, and attenuate with 
   `(org=4721, mask=r)` to make a read-only token; give that token
   to an auditor (you can get more specific here, this is just to get
   you thinking).
   
3. Start with `(org=4721, mask=*) (app=555, mask=*)` and attenuate
   with `(validity-window 2 hours)` to give time-limited access to
   an application to a ops team member investigating an outage.
   
## Entry-Level Macaroon Cryptography

Assume some HMAC secret `R` held by our API. You can see right away how our API could HMAC a single caveat, like `(org=4721, mask=*)`, or even a bunch of them, producing an HMAC tag `T`, tacked onto the message. Even Rails can do that. You as a user can't change these caveats or add to them without breaking `T`. We want to do better.

Instead: start by using `R` to HMAC a nonce, to produce `T_0`. Tack `T_0` on to the end of the message, like so:

```
    Nonce
    T_0
```

You can see how the API could verify `T_0` and thus the nonce.

Now, add the caveat `(org=4721, mask=*)`: take `T_0` off the bottom of the message and use it as the key, instead of `R`, to HMAC the caveat, producing `T_1`. We end up with this message:

```
    Nonce
    (org=4721, mask=*)
    T_1
```

Notice that `T_0` is no longer in the message. Because you don't know `T_0` anymore, you can't reproduce the inputs to `T_1`; the `(org=4721, mask=*)` is stuck there permanently now.

Our API doesn't have this problem, because it knows `R`, the original secret used to sign the nonce. When it gets an attenuated Macaroon, it can simply HMAC the Nonce with `R` to get `T_0`, and then use that to HMAC the org caveat to get `T_1`, and check if it matches the tag on the message.

There you go: a token our API can verify, and that you as a user can extend with additional caveats, by taking the tag off the end of the Macaroon, using it as a key to HMAC your new caveat, and putting that new HMAC at the end of the message. Pretty slick.

## IfPresent Caveats

Another obvious thing you'd want to attenuate a token to: a token that
can only be used to deploy applications, and nothing else, so you can
hand that token off to your CI/CD system.

This should be easily expressed in caveats, except that the access you
need to deploy an application is quirky: Fly.io deployments involve
_builders_ (temporary Fly Machines that run Docker container builders) and _WireGuard access_ (to talk to the builder). 

We have caveats for both of these things:

```
  ((feature-set "builders", mask=*), (feature-set "wg", mask=*))
```

So far so good. Here's the problem, though, when we try to assemble this into a single token:

```
   (org=4721, mask=*)
   ((feature-set "builders", mask=*), (feature-set "wg", mask=*))
   ((app=555, mask=r))
```

We can't do anything with this token. The second caveat allows a request if it's reading or writing to builders or WireGuard. The third caveat allows a request exclusively if it's reading app `555`. Each caveat prohibits the requests intended by the other.

So that's not going to work. Here's what we do:

```
   (org=4721, mask=*)
   (if-present 
      ((feature-set "builders", mask=*), (feature-set "wg", mask=*))
     mask=r)
```

This caveat does what you want. Either:

(1) You're making a builder or wg request, in which case you're fine
    (because `mask=*`).
    
(2) Or, you're doing something else, in which case it had better be
    a read, because the "else" branch of the `if-present` is `r`.

IfPresent is itself just a caveat; one that contains other caveats. You can nest them.

## How Third Party Caveats Work

Things are about to get choppy, and to keep your head above water, you're going to need to grok how 3P caveats work. They're not complicated, but they're subtle.

A 3P caveat is a caveat that is checked by matching it up with a "discharge Macaroon", rather than by looking at the caveat and checking the request against it. We don't really care what's in the discharge Macaroon; we just care that it's cryptographically matched to the 3P caveat. 

Here's how this works. Assume we're some entity --- could be anybody on the Internet, including you, dear reader --- that wants to add a 3P caveat to an existing Macaroon. 

1. We arrange a shared key `KA` between ourselves (the entity adding
   the third-party caveat) and the third-party service that will issue
   discharge Macaroons.
   
2. We generate an ephemeral key `r`, which will serve as the secret HMAC
   key for the discharge Macaroon we want issued.
   
3. We take the HMAC tag `T_n` off the Macaroon we're appending to, just 
   like we normally would to attenuate a token (see [Entry-Level Macaroon Cryptography](#entry-level-macaroon-cryptography) above).
   
4. We use `T_n` to encrypt `r`, our ephemeral key. Call this blob `VID`, 
   or "the verifier ticket".
   
5. We use `KA` to again encrypt `r`, this time with some extra metadata,
   like a set of caveats we want to tell the third-party service about. Call
   this blob `CID`, or "the caveat ticket". 
   
6. We create a caveat out of the tuple `(URL, VID, CID)` (the URL is just a 
   string name for the third-party service, and can be anything).
   
7. We append that caveat to the Macaroon and HMAC it with `T_n`, producing
   `T_n+1`, our new Macaroon tag, just like with an ordinary caveat.

To get a discharge token for a third-party caveat, a user extracts the `CID` 
from the caveat, and gives it to the third-party service. There's no standard way to do this and there doesn't need to be; just assume it's an HTTP POST
endpoint or something. 

The third-party service shares `KA` with the entity
that added the caveat, and so it can decrypt `CID` to recover `r` and the 
metadata, like "make sure this user is logged into Fly.io with an account that
is a member of org `4721`. The service does whatever it does to make sure it's
OK discharging this ticket; if it is, it creates a new Macaroon, using `r` --- which it just recovered by decrypted `CID` --- as the secret HMAC key, and `CID` itself as the nonce. If it wants, it can tack some additional caveats to this discharge Macaroon, like a short `ValidityWindow`. 

Back to our API. You hand us your original root Macaroon, with the 3P caveat attached, and a discharge Macaroon with a matching URL. We check all the caveats until we get to the 3P caveat. We match the 3P caveat with the discharge Macaroon you gave us, by comparing URLs (or `CID`s --- the `CID` in the caveat is the same as nonce of the matching discharge). Then, because we started with the original Macaroon secret `R` and thus know `T_n`, we decrypt the `VID`, recovering `r`. That gives us the secret we need to verify the discharge Macaroon. 

The key things to understand here:

1. We're not talking to third party services when we verify 3P caveats.
   Everything we need is in the Macaroons themselves.
   
2. 3P caveats are a contract between the caveat author and a third-party
   service. The caveat author can be anyone, not just our APIs. 

3. Technically, there doesn't even need to be a third-party service at all.
   You could make a "do-nothing" 3P caveat, just for funsies, by coming up
   with a random URL, `KA` and `r`, and then using them to mint a discharge 
   Macaroon at the same time. We'll never know there wasn't a real service.
   
4. That's because we don't care what the third party service did. All we care
   about is that whoever created the matching discharge Macaroon knew `KA`. We
   assume: if you know `KA`, you checked whatever it was the person who came up 
   with this 3P caveat wanted checked.
   
This all sounds convoluted. It is super powerful. Think of it as a plugin interface for our tokens. You could use 3P tokens to:

* Create a Slack bot with an HTTP POST interface that takes caveat
  tickets from Macaroons and then provides a discharge token if the
  right person thumbs-up-emojis a message on the right channel.
  
* Stand up a Passkeys service with an HTTP endpoint that will mint discharge
  tokens if the requester has authenticated with Passkeys. We don't even 
  support Passkeys yet at Fly.io. Except we do with Macaroons.
  
* Require a second person to approve requests before minting a discharge
  token, to use as a 3P caveat on Macaroons authorizing super-sensitive 
  operations.

## Brief Essay, Semantics Of Checking, Cont'd

Each part of the Macaroon-checking problem has its own pet complexities:

* Verification is complicated because we have thousands of different points
  in our production environment that need to check Macaroons. Macaroons
  rely entirely on symmetric cryptography, so anything that can directly verify
  a Macaroon can also mint new ones, which isn't ideal. 
  
* Clearing is complicated because the information needed to clear a caveat
  is itself distributed; given a request to delete app `555` and a Macaroon
  that says "you can do anything to org `4721`", you still need to know 
  whether app `555` belongs to org `4721` to clear the caveat.

But the underlying design of Macaroons also kills off a lot of complexity, which is why hipsters like us are so taken with them:

* In the main, verification of Macaroon signatures relies entirely on HMAC;
  there's no error-prone public key signatures, no headers that select which
  cryptography you're using, and not a lot of cryptographic mistakes you could
  possibly make.
  
* The clearing model for Macaroons --- just check every caveat individually
  and reject the request if any of them fail --- drastically simplifies 
  authorization logic. There aren't dependencies or other kinds of hidden 
  state between caveats. 

## Service Tokens

This isn't user-servicable detail, but is ideally useful for people who work at Fly.io and at least a little interesting for people who don't.

When we issue tokens to users, they always have a 3P auth caveat pointing to https://api.fly.io/aaa, which requires proof of authentication (either to a specific user, or to a member of a specific organization). This is a 
nice property: it means that by default, every request we handle is implicitly
checking that a logged-in user is behind the request.

Sometimes, though, you want some entity other than a user to carry out actions. 

What you don't want to do is to store the (root, auth) pair of
tokens. There's two problems with that. First, that token pair will
have a `ValidityWindow` that will expire the token, probably at an
inconvenient time. More abstractly, That set forms a bearer token that
can be used _by anyone_ to take actions in our system, which is often
not what you want.

To accomodate this, `tkdb` exposes a "Service Token" API to anyone with 
the Service Token Noise keypair. This API:

1. Accepts a bundle of Macaroons

2. Verifies them (if you don't have a validly authenticated Macaroon,
   the API call fails)
   
3. Recovers all the caveats

4. Strips off `ValidityWindow`, so the caveat set won't expire

5. Strips off https://api.fly.io/aaa 3P caveats, so the caveat
   set no longer requires an auth discharge Macaroon
   
6. Mints a new Macaroon with that caveat set and hands it back to the
   requester.
   
The requester now holds a token equivalently powerful to the original Macaroon, but with no expiry or authentication requirements. 

Another instance of the "service token" problem occurs when our Machines API handles a request that's authenticated not with a Macaroon but with one of our old-school all-powerful OAuth2 tokens. The absolute last thing we want to do is store an OAuth2 token in some random-ass part of our prod environment so we can use it later on. What we do instead is use the OAuth2 token to create a service token on the fly. It's a little complicated, so bear with us:

1. Our Machines API server can use the "Service Token" API to request 
   a Macaroon with an arbitrary set of caveats, _without an accompanying
   3P authentication caveat_. That sounds dangerous, right?
   
2. When TKDB mints that service token Macaroon, it instead adds a 3P 
   caveat pointing to our GraphQL API server. That server can already
   verify OAuth2 tokens. 
   
3. The Machines API server takes the newly-minted service token and presents
   it to our GraphQL API, along with the OAuth2 token the original request
   carried.
   
4. The GraphQL API server checks the OAuth2 token and discharges the 3P
   caveat. 
   
From that point on, the (service token, GQL 3P discharge) pair is sufficient to authorize requests for the associated user.

Note again that in both use cases, the underlying principle is, we want internal components to be able to get service tokens to get jobs done, but only when the chain of events that kicked things off involved an authenticatable 
user. Components in our prod environment cannot just randomly go off and make up tokens.

One other thing to notice: in both cases, we end up with a service token that is pretty powerful (for instance, it's usable without an accompanying authentication token). Attenuation allows us to further restrict the token; for instance, the Machines API can take a service token and slap an additional caveat onto it that makes the token usable only from a particular Fly Machine on a particular worker host; it saves that token and throws away the original, scarier service token.

## Glossary

<dl>
  <dt></dt>
  <dd></dd>

  <dt>Nonce</dt>
  <dd>A random number (perhaps many thousands of bits wide) that is never re-used.</dd>

  <dt>Bearer token/credential</dt>
  <dd>A bearer token independently authorizes a request; there's no protocol that runs between the service the client to further authenticate, but rather, if you supply an acceptable bearer token, you've succeeded in authenticating it. Most tokens (see: OAuth2) are bearer tokens.</dd>

  <dt>Attenuation</dt>
  <dd>The process of adding additional caveats to an existing Macaroon to further restrict with that token allows; anybody can attenuate any Macaroon they have their hands on.</dd>

  <dt>HMAC</dt>
  <dd>A way of computing a SHA2 hash with a key; it can only be (1) computed or (2) checked by holders of that key.</dd>

  <dt>HMAC Tag</dt>
  <dd>The output of HMAC --- a SHA256 hash. Tags are just what the cool kids call HMAC hashes when you slap them onto messages to authenticate them..</dd>

<dt>AEAD</dt>
  <dd>A cipher that authenticates (tamper-proofs) in addition to encrypting it. Most modern cipher constructions express AEADs.</dd>

  <dt>Caveat</dt>
  <dd>A predicate that expresses some restriction on what actions can be taken, relative to an ambient state of "you can do anything at all, chaos reigns".</dd>

  <dt>Third-party (3P) Caveat</dt>
  <dd>An ordinary caveat directly encodes a restriction, like "you can only do read operations, not write operations". A 3P caveat is opaque: our API doesn't look into the guts of the caveat and try to interpret it. Rather, that caveat is satisfied by the client presenting an additional Macaroon token, the "discharge" token, cryptographically linked to the caveat, which proves that some authorized third party said "yep this is OK".</dd>

  <dt>Discharge Macaroon</dt>
  <dd>The token that clears a 3P caveat. A 3P caveat is a demand for a particular discharge token.</dd>
  
  <dt>Root Macaroon</dt>
  <dd>Our ever-shifting terminology for Macaroon you start with, that defines what you can and can't do; the term "root Macaroon" exists to distinguish it from _discharge Macaroons_. We need better names for things.</dd>
  
  <dt>Auth Discharge Macaroon</dt>
  <dd>A Discharge Macaroon issued from Fly.io's authentication endpoint; think of it as a translation gateway from Fly.io's standard authentication (which usually uses all-powerful OAuth2 tokens) to Macaroons.</dd>
  
  <dt>TKDB</dt>
  <dd>The Fly.io ToKen DataBase. A distributed service we deploy on isolated hardware around the world to hold token secrets, so that our production hosts can verify, cache, and invalidate token signatures without pushing token secrets onto thousands of hosts. TKDB exports an internal API secured with 
a Noise transport (think: cool kid mTLS) to Fly.io components like `flyd`.</dd>

  <dt>VID and CID</dt>
  <dd>The "tickets" in a 3P caveat. You only care about the CIDs, or "caveat tickets"; you tear off the CID from a 3P caveat and present it to the third-party service that discharges Macaroons for it; that service decrypts the ticket and uses it to build the discharge token.</dd>

  <dt>Service Tokens</dt>
  <dd>A Service Token is a Macaroon used by a Machine or infrastructure component rather than a person. The difference between a Service Token and an ordinary Macaroon is that the ordinary Macaroon will almost always have an expiration date, and will always have a 3P caveat demanding authentication. A Service Token will have neither.</dd>

</dl>
