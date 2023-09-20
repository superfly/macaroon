package merr

import (
	"fmt"
)

func Append(base error, others ...error) error {
	for _, other := range others {
		if other == nil {
			continue
		}
		if base == nil {
			base = other
		} else {
			base = fmt.Errorf("%w; %w", base, other)
		}
	}

	return base
}
