package providers

import (
	"github.com/google/wire"

	"github.com/go-tangra/go-tangra-lcm/internal/bootstrap"
)

// ProviderSet is the Wire provider set for the bootstrap package
var ProviderSet = wire.NewSet(
	bootstrap.NewBootstrapService,
)
