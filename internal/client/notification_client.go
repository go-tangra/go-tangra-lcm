package client

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/grpc"

	"github.com/go-tangra/go-tangra-common/grpcx"

	notificationv1 "buf.build/gen/go/go-tangra/notification/protocolbuffers/go/notification/service/v1"
	notificationgrpc "buf.build/gen/go/go-tangra/notification/grpc/go/notification/service/v1/servicev1grpc"
)

// NotificationClient wraps gRPC clients for the Notification service.
// It resolves the notification endpoint lazily via ModuleDialer on first use.
type NotificationClient struct {
	dialer *grpcx.ModuleDialer
	log    *log.Helper

	mu       sync.Mutex
	resolved bool
	conn     *grpc.ClientConn

	TemplateService     notificationgrpc.NotificationTemplateServiceClient
	ChannelService      notificationgrpc.NotificationChannelServiceClient
	NotificationService notificationgrpc.NotificationServiceClient
}

// NewNotificationClient creates a new Notification gRPC client that resolves via ModuleDialer.
func NewNotificationClient(ctx *bootstrap.Context, dialer *grpcx.ModuleDialer) (*NotificationClient, func(), error) {
	l := ctx.NewLoggerHelper("notification/client/lcm-service")

	nc := &NotificationClient{
		dialer: dialer,
		log:    l,
	}

	cleanup := func() {
		if nc.conn != nil {
			if err := nc.conn.Close(); err != nil {
				l.Errorf("Failed to close Notification connection: %v", err)
			}
		}
	}

	l.Info("Notification client created (will resolve endpoint on first use)")
	return nc, cleanup, nil
}

// resolve lazily connects to the notification service via ModuleDialer.
func (c *NotificationClient) resolve() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.resolved {
		return nil
	}

	c.log.Info("Resolving notification module endpoint...")
	conn, err := c.dialer.DialModule(context.Background(), "notification", 5, 5*time.Second)
	if err != nil {
		c.log.Errorf("Failed to resolve notification: %v", err)
		return fmt.Errorf("resolve notification: %w", err)
	}

	c.conn = conn
	c.TemplateService = notificationgrpc.NewNotificationTemplateServiceClient(conn)
	c.ChannelService = notificationgrpc.NewNotificationChannelServiceClient(conn)
	c.NotificationService = notificationgrpc.NewNotificationServiceClient(conn)
	c.resolved = true
	c.log.Info("Notification client connected via ModuleDialer")
	return nil
}

// FindChannelByName lists channels and returns the ID of the channel with the given name.
func (c *NotificationClient) FindChannelByName(ctx context.Context, name string) (string, error) {
	if err := c.resolve(); err != nil {
		return "", err
	}

	resp, err := c.ChannelService.ListChannels(ctx, &notificationv1.ListChannelsRequest{})
	if err != nil {
		return "", fmt.Errorf("list channels: %w", err)
	}

	for _, ch := range resp.GetChannels() {
		if ch.GetName() == name {
			return ch.GetId(), nil
		}
	}
	return "", fmt.Errorf("channel %q not found", name)
}

// FindTemplateByName lists templates and returns the one matching the given name.
func (c *NotificationClient) FindTemplateByName(ctx context.Context, name string) (*notificationv1.NotificationTemplate, error) {
	if err := c.resolve(); err != nil {
		return nil, err
	}

	resp, err := c.TemplateService.ListTemplates(ctx, &notificationv1.ListTemplatesRequest{})
	if err != nil {
		return nil, fmt.Errorf("list templates: %w", err)
	}

	for _, tmpl := range resp.GetTemplates() {
		if tmpl.GetName() == name {
			return tmpl, nil
		}
	}
	return nil, nil
}

// CreateTemplate creates a notification template.
func (c *NotificationClient) CreateTemplate(ctx context.Context, req *notificationv1.CreateTemplateRequest) (*notificationv1.NotificationTemplate, error) {
	if err := c.resolve(); err != nil {
		return nil, err
	}

	resp, err := c.TemplateService.CreateTemplate(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("create template: %w", err)
	}
	return resp.GetTemplate(), nil
}

// SendNotification sends a notification via the notification service.
func (c *NotificationClient) SendNotification(ctx context.Context, templateID, recipient string, variables map[string]string) (*notificationv1.NotificationLog, error) {
	if err := c.resolve(); err != nil {
		return nil, err
	}

	resp, err := c.NotificationService.SendNotification(ctx, &notificationv1.SendNotificationRequest{
		TemplateId: templateID,
		Recipient:  recipient,
		Variables:  variables,
	})
	if err != nil {
		return nil, fmt.Errorf("send notification: %w", err)
	}
	return resp.GetNotification(), nil
}
