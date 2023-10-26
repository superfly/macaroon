# Fly.io Macaroon Tokens [![Go Reference](https://pkg.go.dev/badge/github.com/superfly/macaroon.svg)](https://pkg.go.dev/github.com/superfly/macaroon)

This is the extracted Macaroon token code we use for authorization inside of Fly.io. Because [flyctl](https://github.com/superfly/flyctl), our CLI, is open source, it can't fully exploit our tokens unless this library is open source as well. So it is.

We don't think you should use any of this code; it's shrink-wrapped around some peculiar details of our production network, and the data model is Fly-specific. But if it's an interesting to read, that's great too.