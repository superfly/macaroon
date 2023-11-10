package tp

import (
	"testing"

	"github.com/alecthomas/assert/v2"
)

func TestMemoryStoreSecrets(t *testing.T) {
	ms, err := NewMemoryStore(PrefixMunger("/user/"), 100)
	assert.NoError(t, err)

	assert.Equal(t, 32, len(ms.secret))

	x, y := ms.ticketSecrets([]byte("hi"))
	assert.Equal(t, 32, len(x))
	assert.Equal(t, 32, len(y))

	a := &StoreData{Ticket: []byte("a")}
	aUS, aPS, err := ms.Put(a)
	assert.NoError(t, err)

	b := &StoreData{Ticket: []byte("b")}
	bUS, bPS, err := ms.Put(b)
	assert.NoError(t, err)

	sd, err := ms.GetByUserSecret(aUS)
	assert.NoError(t, err)
	assert.Equal(t, []byte("a"), sd.Ticket)
	_, err = ms.GetByPollSecret(aUS)
	assert.Equal(t, errNotFound, err)

	sd, err = ms.GetByPollSecret(aPS)
	assert.NoError(t, err)
	assert.Equal(t, []byte("a"), sd.Ticket)
	_, err = ms.GetByUserSecret(aPS)
	assert.Equal(t, errNotFound, err)

	sd, err = ms.GetByUserSecret(bUS)
	assert.NoError(t, err)
	assert.Equal(t, []byte("b"), sd.Ticket)
	_, err = ms.GetByPollSecret(bUS)
	assert.Equal(t, errNotFound, err)

	sd, err = ms.GetByPollSecret(bPS)
	assert.NoError(t, err)
	assert.Equal(t, []byte("b"), sd.Ticket)
	_, err = ms.GetByUserSecret(bPS)
	assert.Equal(t, errNotFound, err)

	assert.NoError(t, ms.DeleteByPollSecret(aPS))

	_, err = ms.GetByPollSecret(aPS)
	assert.Equal(t, errNotFound, err)
	_, err = ms.GetByUserSecret(aUS)
	assert.Equal(t, errNotFound, err)

	sd, err = ms.GetByUserSecret(bUS)
	assert.NoError(t, err)
	assert.Equal(t, []byte("b"), sd.Ticket)
	_, err = ms.GetByPollSecret(bUS)
	assert.Equal(t, errNotFound, err)

	sd, err = ms.GetByPollSecret(bPS)
	assert.NoError(t, err)
	assert.Equal(t, []byte("b"), sd.Ticket)
	_, err = ms.GetByUserSecret(bPS)
	assert.Equal(t, errNotFound, err)

	bb := *b
	bb.ResponseBody = []byte{1, 2, 3}
	bbUS, bbPS, err := ms.Put(&bb)
	assert.NoError(t, err)
	assert.Equal(t, bUS, bbUS)
	assert.Equal(t, bPS, bbPS)

	sd, err = ms.GetByUserSecret(bUS)
	assert.NoError(t, err)
	assert.Equal(t, []byte("b"), sd.Ticket)
	assert.Equal(t, []byte{1, 2, 3}, sd.ResponseBody)
	_, err = ms.GetByPollSecret(bUS)
	assert.Equal(t, errNotFound, err)

	sd, err = ms.GetByPollSecret(bPS)
	assert.NoError(t, err)
	assert.Equal(t, []byte("b"), sd.Ticket)
	assert.Equal(t, []byte{1, 2, 3}, sd.ResponseBody)
	_, err = ms.GetByUserSecret(bPS)
	assert.Equal(t, errNotFound, err)
}
