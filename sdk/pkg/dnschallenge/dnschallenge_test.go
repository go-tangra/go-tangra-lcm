package dnschallenge

// The client against an in-process gRPC server that decodes the request with
// the same message descriptors (the dns module's test proves compatibility
// with the real dns.v1 server): method names, field numbers, the response
// zone, and typed errors that never carry the server's message.

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

type seen struct {
	method string
	fields [4]string
}

func serve(t *testing.T, fail error) (*Client, *seen) {
	t.Helper()
	got := &seen{}
	handler := func(srv any, stream grpc.ServerStream) error {
		m, _ := grpc.MethodFromServerStream(stream)
		got.method = m
		req := dynamicpb.NewMessage(reqDesc)
		if err := stream.RecvMsg(req); err != nil {
			return err
		}
		for i := 1; i <= 4; i++ {
			got.fields[i-1] = req.Get(reqDesc.Fields().ByNumber(protoreflect.FieldNumber(i))).String()
		}
		if fail != nil {
			return fail
		}
		resp := dynamicpb.NewMessage(respDesc)
		resp.Set(respDesc.Fields().ByNumber(1), protoreflect.ValueOfString("example.test."))
		return stream.SendMsg(resp)
	}
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer(grpc.UnknownServiceHandler(handler))
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return New(conn), got
}

func TestPresentAndCleanUp(t *testing.T) {
	c, got := serve(t, nil)
	ctx := context.Background()
	zone, err := c.Present(ctx, "t1", "*.example.test", "_acme-challenge.example.test", "v1")
	if err != nil || zone != "example.test." {
		t.Fatalf("present = %q %v", zone, err)
	}
	if got.method != PresentMethod || got.fields != [4]string{"t1", "*.example.test", "_acme-challenge.example.test", "v1"} {
		t.Fatalf("seen = %+v", got)
	}
	if zone, err = c.CleanUp(ctx, "t2", "example.test", "_acme-challenge.example.test", "v2"); err != nil || zone != "example.test." || got.method != CleanUpMethod || got.fields[0] != "t2" {
		t.Fatalf("cleanup = %q %v %+v", zone, err, got)
	}
}

func TestErrors(t *testing.T) {
	for code, want := range map[codes.Code]error{
		codes.NotFound: ErrNotFound, codes.PermissionDenied: ErrPermissionDenied, codes.Unauthenticated: ErrPermissionDenied,
		codes.InvalidArgument: ErrInvalid, codes.FailedPrecondition: ErrPrecondition, codes.Unavailable: ErrUnavailable,
		codes.DeadlineExceeded: ErrUnavailable, codes.Internal: ErrFailed,
	} {
		c, _ := serve(t, status.Error(code, "secret server detail"))
		_, err := c.Present(context.Background(), "t", "d", "f", "v")
		if !errors.Is(err, want) || strings.Contains(err.Error(), "secret server detail") {
			t.Errorf("%v: %v", code, err)
		}
	}
}
