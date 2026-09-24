// Package dnschallenge is lcm's client for the platform DNS module's ACME
// DNS-01 surface, dns.v1.Challenges (Present/CleanUp over SPIFFE mTLS), used
// by the "freya-dns" ACME provider. The DNS module serves it to the lcm
// identity only and writes only "_acme-challenge" TXT values inside the
// tenant's own zones.
//
// The two messages (dns.v1.ChallengeRequest {tenant_id=1, domain=2, fqdn=3,
// value=4} and dns.v1.ChallengeResponse {zone=1}, services/dns/api/proto) are
// described here with protobuf dynamic messages instead of importing the dns
// module's generated stubs: a Go module dependency of lcm on services/dns
// would force a replace directive for dns (and its dependencies) into every
// module that requires lcm. The wire compatibility with the real dns.v1
// server is proven by a test in the dns module. Errors are typed sentinels
// mapped from the gRPC status code; the server's message text never surfaces.
package dnschallenge

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

// Full method names of dns.v1.Challenges.
const (
	PresentMethod = "/dns.v1.Challenges/Present"
	CleanUpMethod = "/dns.v1.Challenges/CleanUp"
)

// Typed errors (mapped from the gRPC status code only).
var (
	ErrNotFound         = errors.New("dnschallenge: no zone of the tenant contains the name")
	ErrPermissionDenied = errors.New("dnschallenge: permission denied")
	ErrInvalid          = errors.New("dnschallenge: invalid request")
	ErrPrecondition     = errors.New("dnschallenge: precondition failed")
	ErrUnavailable      = errors.New("dnschallenge: dns unavailable")
	ErrFailed           = errors.New("dnschallenge: request failed")
)

// descriptors of the two dns.v1 messages (built once).
var reqDesc, respDesc = mustDescriptors()

func str(name string, num int32) *descriptorpb.FieldDescriptorProto {
	return &descriptorpb.FieldDescriptorProto{Name: proto.String(name), JsonName: proto.String(name), Number: proto.Int32(num),
		Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(), Type: descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum()}
}

func mustDescriptors() (protoreflect.MessageDescriptor, protoreflect.MessageDescriptor) {
	fd := &descriptorpb.FileDescriptorProto{
		Name:    proto.String("lcm/dnschallenge/dns_v1_challenges.proto"),
		Package: proto.String("dns.v1"),
		Syntax:  proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{
			{Name: proto.String("ChallengeRequest"), Field: []*descriptorpb.FieldDescriptorProto{
				str("tenant_id", 1), str("domain", 2), str("fqdn", 3), str("value", 4)}},
			{Name: proto.String("ChallengeResponse"), Field: []*descriptorpb.FieldDescriptorProto{str("zone", 1)}},
		},
	}
	f, err := protodesc.NewFile(fd, nil)
	if err != nil {
		panic(fmt.Sprintf("dnschallenge: descriptors: %v", err))
	}
	return f.Messages().ByName("ChallengeRequest"), f.Messages().ByName("ChallengeResponse")
}

// Client calls dns.v1.Challenges over a caller-provided (SPIFFE-mTLS)
// connection to the DNS module.
type Client struct{ conn grpc.ClientConnInterface }

// New builds a client; it does not dial.
func New(conn grpc.ClientConnInterface) *Client { return &Client{conn: conn} }

func request(tenantID, domain, fqdn, value string) *dynamicpb.Message {
	m := dynamicpb.NewMessage(reqDesc)
	f := reqDesc.Fields()
	m.Set(f.ByNumber(1), protoreflect.ValueOfString(tenantID))
	m.Set(f.ByNumber(2), protoreflect.ValueOfString(domain))
	m.Set(f.ByNumber(3), protoreflect.ValueOfString(fqdn))
	m.Set(f.ByNumber(4), protoreflect.ValueOfString(value))
	return m
}

func (c *Client) call(ctx context.Context, method, tenantID, domain, fqdn, value string) (string, error) {
	resp := dynamicpb.NewMessage(respDesc)
	if err := c.conn.Invoke(ctx, method, request(tenantID, domain, fqdn, value), resp); err != nil {
		return "", mapErr(err)
	}
	return resp.Get(respDesc.Fields().ByNumber(1)).String(), nil
}

// Present publishes an ACME DNS-01 value at fqdn in the tenant's zone and
// returns the zone written.
func (c *Client) Present(ctx context.Context, tenantID, domain, fqdn, value string) (string, error) {
	return c.call(ctx, PresentMethod, tenantID, domain, fqdn, value)
}

// CleanUp removes an ACME DNS-01 value from fqdn (absent = success) and
// returns the zone cleaned.
func (c *Client) CleanUp(ctx context.Context, tenantID, domain, fqdn, value string) (string, error) {
	return c.call(ctx, CleanUpMethod, tenantID, domain, fqdn, value)
}

func mapErr(err error) error {
	var sentinel error
	switch status.Code(err) {
	case codes.NotFound:
		sentinel = ErrNotFound
	case codes.PermissionDenied, codes.Unauthenticated:
		sentinel = ErrPermissionDenied
	case codes.InvalidArgument:
		sentinel = ErrInvalid
	case codes.FailedPrecondition:
		sentinel = ErrPrecondition
	case codes.Unavailable, codes.DeadlineExceeded:
		sentinel = ErrUnavailable
	default:
		sentinel = ErrFailed
	}
	return fmt.Errorf("%w (%s)", sentinel, status.Code(err))
}
