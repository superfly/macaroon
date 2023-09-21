package merr

import (
	"errors"
	"testing"

	"github.com/alecthomas/assert/v2"
)

func TestAppend(t *testing.T) {
	var (
		e1 = errors.New("1")
		e2 = errors.New("2")
		e3 = errors.New("3")
	)

	assert.Equal(t, "1", Append(e1, nil).Error())
	assert.Equal(t, "1", Append(nil, e1).Error())
	assert.Equal(t, "1", Append(nil, nil, e1).Error())
	assert.Equal(t, "1", Append(nil, Append(e1)).Error())
	assert.Equal(t, "1; 2", Append(e1, e2).Error())
	assert.Equal(t, "1; 2", Append(nil, e1, e2).Error())
	assert.Equal(t, "1; 2", Append(e1, nil, e2).Error())
	assert.Equal(t, "1; 2; 3", Append(e1, Append(e2, e3)).Error())

	assert.True(t, errors.Is(Append(e1, nil), e1))
	assert.True(t, errors.Is(Append(nil, e1), e1))
	assert.True(t, errors.Is(Append(nil, nil, e1), e1))
	assert.True(t, errors.Is(Append(nil, Append(e1)), e1))
	assert.True(t, errors.Is(Append(e1, e2), e1))
	assert.True(t, errors.Is(Append(e1, e2), e2))
	assert.True(t, errors.Is(Append(nil, e1, e2), e1))
	assert.True(t, errors.Is(Append(nil, e1, e2), e2))
	assert.True(t, errors.Is(Append(e1, nil, e2), e1))
	assert.True(t, errors.Is(Append(e1, nil, e2), e2))
	assert.True(t, errors.Is(Append(e1, Append(e2, e3)), e1))
	assert.True(t, errors.Is(Append(e1, Append(e2, e3)), e2))
	assert.True(t, errors.Is(Append(e1, Append(e2, e3)), e3))

	assert.Zero(t, Append(nil))
	assert.Zero(t, Append(nil, nil))
}
