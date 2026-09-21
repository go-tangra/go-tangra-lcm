package httpapi

import (
	"errors"

	"github.com/go-freya/freya/services/lcm/internal/deploy"
)

func asDeployValidation(err error, target **deploy.ValidationError) bool {
	return errors.As(err, target)
}
