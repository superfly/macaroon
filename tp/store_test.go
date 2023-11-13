package tp

import (
	"context"
	"testing"

	"github.com/alecthomas/assert/v2"
)

func TestMemoryStoreSecrets(t *testing.T) {
	ctx := context.Background()

	ms, err := NewMemoryStore(PrefixMunger("/user/"), 100)
	assert.NoError(t, err)

	a := &StoreData{Ticket: []byte("a")}
	aUS, aPS, err := ms.Insert(ctx, a)
	assert.NoError(t, err)

	b := &StoreData{Ticket: []byte("b")}
	bUS, bPS, err := ms.Insert(ctx, b)
	assert.NoError(t, err)

	sd, err := ms.GetByUserSecret(ctx, aUS)
	assert.NoError(t, err)
	assert.Equal(t, []byte("a"), sd.Ticket)
	_, err = ms.GetByPollSecret(ctx, aUS)
	assert.Equal(t, errNotFound, err)

	sd, err = ms.GetByPollSecret(ctx, aPS)
	assert.NoError(t, err)
	assert.Equal(t, []byte("a"), sd.Ticket)
	_, err = ms.GetByUserSecret(ctx, aPS)
	assert.Equal(t, errNotFound, err)

	sd, err = ms.GetByUserSecret(ctx, bUS)
	assert.NoError(t, err)
	assert.Equal(t, []byte("b"), sd.Ticket)
	_, err = ms.GetByPollSecret(ctx, bUS)
	assert.Equal(t, errNotFound, err)

	sd, err = ms.GetByPollSecret(ctx, bPS)
	assert.NoError(t, err)
	assert.Equal(t, []byte("b"), sd.Ticket)
	_, err = ms.GetByUserSecret(ctx, bPS)
	assert.Equal(t, errNotFound, err)

	err = ms.DeleteByUserSecret(ctx, aPS)
	assert.Equal(t, errNotFound, err)
	err = ms.DeleteByPollSecret(ctx, aUS)
	assert.Equal(t, errNotFound, err)
	assert.NoError(t, ms.DeleteByPollSecret(ctx, aPS))

	_, err = ms.GetByPollSecret(ctx, aPS)
	assert.Equal(t, errNotFound, err)
	_, err = ms.GetByUserSecret(ctx, aUS)
	assert.Equal(t, errNotFound, err)

	sd, err = ms.GetByUserSecret(ctx, bUS)
	assert.NoError(t, err)
	assert.Equal(t, []byte("b"), sd.Ticket)
	_, err = ms.GetByPollSecret(ctx, bUS)
	assert.Equal(t, errNotFound, err)

	sd, err = ms.GetByPollSecret(ctx, bPS)
	assert.NoError(t, err)
	assert.Equal(t, []byte("b"), sd.Ticket)
	_, err = ms.GetByUserSecret(ctx, bPS)
	assert.Equal(t, errNotFound, err)

	b.ResponseBody = []byte{1, 2, 3}
	err = ms.UpdateByPollSecret(ctx, bPS, b)
	assert.NoError(t, err)

	sd, err = ms.GetByUserSecret(ctx, bUS)
	assert.NoError(t, err)
	assert.Equal(t, []byte("b"), sd.Ticket)
	assert.Equal(t, []byte{1, 2, 3}, sd.ResponseBody)
	_, err = ms.GetByPollSecret(ctx, bUS)
	assert.Equal(t, errNotFound, err)

	sd, err = ms.GetByPollSecret(ctx, bPS)
	assert.NoError(t, err)
	assert.Equal(t, []byte("b"), sd.Ticket)
	assert.Equal(t, []byte{1, 2, 3}, sd.ResponseBody)
	_, err = ms.GetByUserSecret(ctx, bPS)
	assert.Equal(t, errNotFound, err)

	b.ResponseBody = []byte{4, 5, 6}
	err = ms.UpdateByUserSecret(ctx, bUS, b)
	assert.NoError(t, err)

	sd, err = ms.GetByUserSecret(ctx, bUS)
	assert.NoError(t, err)
	assert.Equal(t, []byte("b"), sd.Ticket)
	assert.Equal(t, []byte{4, 5, 6}, sd.ResponseBody)
	_, err = ms.GetByPollSecret(ctx, bUS)
	assert.Equal(t, errNotFound, err)

	sd, err = ms.GetByPollSecret(ctx, bPS)
	assert.NoError(t, err)
	assert.Equal(t, []byte("b"), sd.Ticket)
	assert.Equal(t, []byte{4, 5, 6}, sd.ResponseBody)
	_, err = ms.GetByUserSecret(ctx, bPS)
	assert.Equal(t, errNotFound, err)

	b.ResponseBody = []byte{9, 9, 9}
	err = ms.UpdateByPollSecret(ctx, bUS, b)
	assert.Equal(t, errNotFound, err)
	err = ms.UpdateByUserSecret(ctx, bPS, b)
	assert.Equal(t, errNotFound, err)

	sd, err = ms.GetByUserSecret(ctx, bUS)
	assert.NoError(t, err)
	assert.Equal(t, []byte("b"), sd.Ticket)
	assert.Equal(t, []byte{4, 5, 6}, sd.ResponseBody)
	_, err = ms.GetByPollSecret(ctx, bUS)
	assert.Equal(t, errNotFound, err)

	sd, err = ms.GetByPollSecret(ctx, bPS)
	assert.NoError(t, err)
	assert.Equal(t, []byte("b"), sd.Ticket)
	assert.Equal(t, []byte{4, 5, 6}, sd.ResponseBody)
	_, err = ms.GetByUserSecret(ctx, bPS)
	assert.Equal(t, errNotFound, err)

	assert.NoError(t, ms.DeleteByUserSecret(ctx, bUS))

	_, err = ms.GetByPollSecret(ctx, bPS)
	assert.Equal(t, errNotFound, err)
	_, err = ms.GetByUserSecret(ctx, bUS)
	assert.Equal(t, errNotFound, err)
}
