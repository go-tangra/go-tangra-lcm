// Package fuzz holds the fuzz targets of the lcm module: parsers and encoders
// that face workload or module input must never panic and must refuse what the
// contracts refuse (CSR, SPIFFE id, PEM/bundle, SSE frame, enrollment token,
// webhook signature, backup).
package fuzz
