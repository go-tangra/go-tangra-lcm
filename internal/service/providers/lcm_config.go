package providers

import (
	"github.com/go-tangra/go-tangra-lcm/internal/conf"

	"github.com/tx7do/kratos-bootstrap/bootstrap"
)

// ProvideLCMConfig extracts the LCM config from the bootstrap context
func ProvideLCMConfig(ctx *bootstrap.Context) *conf.LCM {
	customConfig, ok := ctx.GetCustomConfig("lcm")
	if !ok {
		return nil
	}
	lcmConfig, ok := customConfig.(*conf.LCM)
	if !ok || lcmConfig == nil {
		return nil
	}
	return lcmConfig
}
