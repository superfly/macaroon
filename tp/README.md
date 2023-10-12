# Third Party Discharge Protocol

Clients wishing to communicate with macaroon-authenticated services (1st parties or 1ps) require a mechanism for communicating with third parties (3ps) in order to obtain discharge macaroons that satisfy any third party caveats in the 1st party macaroon. This document defines a protocol allowing clients to request discharge macaroons from 3rd parties.

If this reads like gibberish so far, check out the [background](#background) section.

There are (at least) three possible intents behind a 3p caveat:

1. The need to authorize the principal. E.g. to authenticate a user.
1. The need to authorize the client. E.g. to enforce a rate-limiting requirements on clients.
1. The need to authorize some ambient state. E.g. to only allow tokens to be used on Tuesdays.

The client may be the principal themselves (e.g. a user using cURL or other CLI tooling) or may be another entity acting on the principal's behalf (e.g. a service using the 1p API for the user).

## Protocol Flows

Clients initiate their request for a discharge macaroon by making an HTTP POST request directly to the 3p service:

```http
POST /.well-known/macfly/3p
Host: <3p-location>
Content-Type: application/json
Cookie: <principal-cookie>
Authorization: <client-credentials>

{
    "ticket": "<base64 encoded ticket>"
}
```

The request body is a JSON encoded object with the base64 encoded ticket to be discharged specified in the `ticket` field. If the 3p's location identifier includes a URL path, it will be included before the `/.well-known` path segment.

The client MAY authenticate itself using the `Authorization` header if the 3p and client have established a mechanism for client authentication. The client MAY maintain a per-principal cookie jar allowing for future discharge flows to be expedited.

The 3p will respond with status 201 on success:

```http
HTTP/1.1 201 Created
Content-Type: application/json
Set-Cookie: <principal-cookie>

{
    "discharge": "base64 encoded discharge macaroon",
    "poll": "/url/or/path/to/poll",
}
```

If an error is encountered, an appropriate HTTP status code will be returned and the response body will contain a JSON object with an `error` field:

```http
HTTP/1.1 420 Enhance your calm
Content-Type: application/json

{
    "error": "too many requests. try again later"
}
```

The contents of the JSON object returned in successful responses will indicate how the client may proceed with obtaining a discharge for the requested ticket. This will vary based on the capabilities of the client and 3p and on the presence of client authentication or principal cookies. 3ps will only need to implement a subset of the following response types, but clients should be prepared to handle any of them.

### Immediate Response

If no client<->3p interaction beyond the initial request is required, the server may respond with an `discharge` field in the response body:

```http
HTTP/1.1 201 Created
Content-Type: application/json

{
    "discharge": "base64 encoded discharge macaroon"
}
```

This may be the case when the 3p caveat was intended to authorize ambient state or the client itself or when the principal-cookie provided by the client adequately authorized the principal.

### Poll Response

If no client<->3p interaction beyond the initial request is required, but the server was not able to respond with a discharge token immediately, the server may respond with a `poll_url` field in the response body:

```http
HTTP/1.1 201 Created
Content-Type: application/json

{
    "poll_url": "<absolute or relative url to poll>"
}
```

This may be the case if the 3p needs to authorize the request via some out-of-band process, like sending the user a confirmation link via email or SMS.

The client may continue to request the specified polling endpoint to check if the discharge is ready. If the discharge is not ready yet, the server will respond with an empty response with status code 202.

```http
HTTP/1.1 202 Accepted
```

Once the discharge is ready, the server will return it with a status code 200:

```http
HTTP/1.1 200 Ok
Content-Type: application/json

{
    "discharge": "base64 encoded discharge macaroon"
}
```

If the flow completed unsuccessfully, the 3p will return a 200 response with a JSON body containing `error` field:

```http
HTTP/1.1 200 Ok
Content-Type: application/json

{
    "error": "user rejected approval"
}
```

The poll URL MUST include enough entropy to make it unguessable. Clients maintaining a cookie jar for the principal should continue sending `Cookie` header in poll requests and processing `Set-Cookie` headers in responses. Clients capable of authenticating themselves to the 3p should continue sending the `Authorization` header on poll requests.

Once the flow has completed and the server has returned a single 200 response to a polling request, the server may deregister the polling endpoint and begin returning 404 status codes. If the flow completes and the 3p hasn't received a request to the polling endpoint within a reasonable amount of time, they may also deregister the polling endpoint.

### User Interactive Response

The 3p may need to interact directly with the principal by having them performing some flow via a web browser. For example, the 3p might need the user do a WebAuthn exchange or solve a CAPTCHA. In this case, the 3p's response body will include a `user_interactive` field:

```http
HTTP/1.1 201 Created
Content-Type: application/json

{
    "user_interactive": {
        "user_url": "<url to navigate user to>",
        "poll_url": "<absolute or relative url to poll>"
    }
}
```

To continue with this flow, the client may navigate the user to the specified `user_url` where they will interact with the 3p directly. Web-based clients that are interacting with the user via their web browser can achieve this navigation by redirecting the user. Other clients (e.g. CLI apps) can display the URL and instruct the user to visit it.

If the client wants the user to be redirected to a specific URL once the their interaction with the 3p is completed, they may include add a `return_to` parameter to the query string when navigating the user to the `user_url`. This may be useful for clients that don't want to poll the `poll_url`, but would rather receive a request to indicate the completion of the flow.

The client may make requests to the `poll_url` as they would for the [Poll Response](#poll-response) described above.

## Background

Third party (3p) caveats require the principal to fetch a discharge macaroon from a third party service before the base macaroon is considered valid.

For example, Alice wants to give Bob a https://service.com macaroon that only works once he's proven his identity to https://login.com. She adds an https://login.com 3p caveat requiring `user=bob` to her https://service.com macaroon and then gives it to Bob. Bob proves his identity to https://login.com and receives a discharge macaroon. He can how use the two macaroons together to access https://service.com.

### Cast of characters

- _First party (1p)_ - The service that requires macaroon authentication. In the opening example, this is https://service.com
- _Third party (3p)_ - A service that is capable of issuing discharge macaroons. In the opening example, this is https://login.com
- _Macaroon attenuator_ - An entity that adds caveats to macaroon(s) in their possession. This could be the 1p during initial macaroon issuance, or the user once they posses a macaroon. In the opening example, this is Alice
- _Principal_ - An entity using macaroon(s) to access the 1p service. In the opening example, this is Bob

### Third Party Caveat Mechanics

For each 3p caveat, the macaroon attenuator generates a random key that will be used to issue discharge macaroons. It encrypts this key, along with a set of caveats that must be checked by the 3p, under a symmetric key that is shared with the 3p. This encrypted blob is called the ticket and is stored in the 3p caveat. When the 3p receives a ticket, it is able to decrypt it, clear the included caveats, and issue a discharge macaroon using the random key. The `kid` field of the discharge macaroon's `nonce` is the encrypted ticket. This allows the discharge macaroon to be easily matched with the 3p caveat it was generated for.

```go
type Ticket struct {
	DischargeKey []byte
	Caveats      CaveatSet
}
```

The 1p must also be able to learn the discharge key in order to clear the discharge macaroon. To facilitate this, the random discharge key is also encrypted under the current macaroon tail (signature), using it as a symmetric key. This encrypted blob is called the VerifierKey and is also stored in the 3p caveat.

```go
type Caveat3P struct {
	Location    string
	VerifierKey []byte
	Ticket      []byte
}
```

The flow, in its entirely, is as follows:

- Alice:
    1. Having an https://service.com macaroon and a symmetric key shared with https://login.com,
    1. Generates a random discharge key
    1. Encrypts the discharge key and a `user=bob` caveat under the key shared with https://login.com
    1. Encrypts the discharge key under the current macaroon tail
    1. Adds a `Caveat3P` to her https://service.com macaroon with `location=https://login.com`, the ticket, and the VerifierKey.
    1. Gives the updated https://service.com macaroon to Bob
- Bob:
    1. Having the updated https://service.com macaroon,
    1. Searches the macaroon for https://login.com caveats that it doesn't already posses discharge tokens for
    1. Extracts the encrypted ticket from the 3P caveat
    1. Makes a request that https://login.com furnish an appropriate discharge macaroon to clear the 3p caveat
- https://login.com:
    1. Receiving the discharge request,
    1. Decrypts the ticket using the symmetric key they share with Alice
    1. Clear any caveats contained in the decrypted ticket
        - `user=bob` caveat: Validate Bob's identity, for example using username/password
    1. Use the discharge secret from the decrypted ticket to issue a macaroon whose `nonce.kid` is the encrypted ticket
    1. Return this discharge token to Bob
- Bob:
    1. Having received the discharge macaroon,
    1. Makes a request to https://service.com including the https://service.com macaroon and discharge macaroon
- https://service.com:
    1. Receiving a request from Bob,
    1. Begins validation of the https://service.com macaroon
        1. Encountering a 3p caveat,
        1. Searches provided discharge macaroons for one whose `nonce.kid` matches the 3p caveat's encrypted ticket
        1. Decrypts the discharge secret from the VerifierKey using the tail signature from this point in the https://service.com macaroon validation process as a symmetric key
        1. Validates the discharge macaroon using the recovered discharge secret
    1. Clears remaining caveats in the https://service.com macaroon
    1. Processes the Bob's request, having successfully validated his macaroons.