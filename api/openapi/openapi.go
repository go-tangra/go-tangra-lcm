// Package openapi embeds the lcm browser API contract.
package openapi

import _ "embed"

// LCM is the OpenAPI 3.1 document served and validated by the service.
//
//go:embed lcm.yaml
var LCM []byte
