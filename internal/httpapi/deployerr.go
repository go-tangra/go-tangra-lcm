package httpapi

import (
	"errors"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/deploy"
)

func asDeployValidation(err error, target **deploy.ValidationError) bool {
	return errors.As(err, target)
}
