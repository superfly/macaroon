package tp

import (
	"context"
	"testing"
	"time"

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

func TestBackoffBeforeDeadline(t *testing.T) {
	t.Run("no deadline", func(t *testing.T) {
		assert.Equal(t, time.Hour, boBeforeDeadline(context.Background(), time.Hour))
	})

	t.Run("backoff lands before deadline", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()

		assert.Equal(t, time.Second, boBeforeDeadline(ctx, time.Second))
	})

	t.Run("backoff sleeps past deadline", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// clamped to just under the remaining time, so a final poll lands
		// before the deadline instead of after it.
		bo := boBeforeDeadline(ctx, time.Hour)
		assert.True(t, bo > 8*time.Second, "got %s", bo)
		assert.True(t, bo < 9*time.Second, "got %s", bo)
	})

	t.Run("deadline too close for another poll", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		// nothing useful to clamp to: leave the backoff alone and let the
		// context expire.
		assert.Equal(t, time.Hour, boBeforeDeadline(ctx, time.Hour))
	})

	t.Run("expired deadline", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 0)
		defer cancel()

		assert.Equal(t, time.Hour, boBeforeDeadline(ctx, time.Hour))
	})
}
