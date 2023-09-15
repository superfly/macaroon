package macaroon

import (
	"errors"
	"testing"

	"github.com/alecthomas/assert/v2"
)

func TestAppendErrs(t *testing.T) {
	var (
		e1 = errors.New("1")
		e2 = errors.New("2")
		e3 = errors.New("3")
	)

	assert.Equal(t, "1", appendErrs(e1, nil).Error())
	assert.Equal(t, "1", appendErrs(nil, e1).Error())
	assert.Equal(t, "1", appendErrs(nil, nil, e1).Error())
	assert.Equal(t, "1", appendErrs(nil, appendErrs(e1)).Error())
	assert.Equal(t, "1; 2", appendErrs(e1, e2).Error())
	assert.Equal(t, "1; 2", appendErrs(nil, e1, e2).Error())
	assert.Equal(t, "1; 2", appendErrs(e1, nil, e2).Error())
	assert.Equal(t, "1; 2; 3", appendErrs(e1, appendErrs(e2, e3)).Error())

	assert.True(t, errors.Is(appendErrs(e1, nil), e1))
	assert.True(t, errors.Is(appendErrs(nil, e1), e1))
	assert.True(t, errors.Is(appendErrs(nil, nil, e1), e1))
	assert.True(t, errors.Is(appendErrs(nil, appendErrs(e1)), e1))
	assert.True(t, errors.Is(appendErrs(e1, e2), e1))
	assert.True(t, errors.Is(appendErrs(e1, e2), e2))
	assert.True(t, errors.Is(appendErrs(nil, e1, e2), e1))
	assert.True(t, errors.Is(appendErrs(nil, e1, e2), e2))
	assert.True(t, errors.Is(appendErrs(e1, nil, e2), e1))
	assert.True(t, errors.Is(appendErrs(e1, nil, e2), e2))
	assert.True(t, errors.Is(appendErrs(e1, appendErrs(e2, e3)), e1))
	assert.True(t, errors.Is(appendErrs(e1, appendErrs(e2, e3)), e2))
	assert.True(t, errors.Is(appendErrs(e1, appendErrs(e2, e3)), e3))

	assert.Zero(t, appendErrs(nil))
	assert.Zero(t, appendErrs(nil, nil))
}
