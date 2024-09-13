package tp

import (
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/hashicorp/go-cleanhttp"
)

func TestClient(t *testing.T) {
	h := cleanhttp.DefaultClient()

	c1 := NewClient("http://foo", WithHTTP(h), WithAuthentication("foo", "bar"))
	c2 := NewClient("http://foo", WithHTTP(h), WithAuthentication("foo", "baz"))

	assert.Equal(t, "bar", c1.http.Transport.(*authenticatedHTTP).auth["foo"])
	assert.Equal(t, "baz", c2.http.Transport.(*authenticatedHTTP).auth["foo"])
}
