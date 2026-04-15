package client

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"

	"github.com/go-tangra/go-tangra-common/grpcx"

	deployerv1 "buf.build/gen/go/go-tangra/deployer/protocolbuffers/go/deployer/service/v1"
	deployergrpc "buf.build/gen/go/go-tangra/deployer/grpc/go/deployer/service/v1/servicev1grpc"
)

// DeployerClient wraps gRPC clients for the Deployer service.
// It resolves the deployer endpoint lazily via ModuleDialer on first use.
type DeployerClient struct {
	dialer *grpcx.ModuleDialer
	log    *log.Helper

	mu       sync.Mutex
	resolved bool
	conn     *grpc.ClientConn

	DeploymentService    deployergrpc.DeploymentServiceClient
	TargetService        deployergrpc.DeploymentTargetServiceClient
	ConfigurationService deployergrpc.TargetConfigurationServiceClient
	JobService           deployergrpc.DeploymentJobServiceClient
}

// NewDeployerClient creates a new Deployer gRPC client that resolves via ModuleDialer.
func NewDeployerClient(ctx *bootstrap.Context, dialer *grpcx.ModuleDialer) (*DeployerClient, func(), error) {
	l := ctx.NewLoggerHelper("deployer/client/lcm-service")

	dc := &DeployerClient{
		dialer: dialer,
		log:    l,
	}

	cleanup := func() {
		if dc.conn != nil {
			if err := dc.conn.Close(); err != nil {
				l.Errorf("Failed to close Deployer connection: %v", err)
			}
		}
	}

	l.Info("Deployer client created (will resolve endpoint on first use)")
	return dc, cleanup, nil
}

// resolve lazily connects to the deployer service via ModuleDialer.
func (c *DeployerClient) resolve() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.resolved {
		return nil
	}

	c.log.Info("Resolving deployer module endpoint...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := c.dialer.DialModule(ctx, "deployer", 2, 3*time.Second)
	if err != nil {
		c.log.Errorf("Failed to resolve deployer: %v", err)
		return fmt.Errorf("resolve deployer: %w", err)
	}

	// Verify the connection is usable by waiting for it to become ready
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer waitCancel()
	conn.Connect()
	if !conn.WaitForStateChange(waitCtx, connectivity.Idle) {
		c.log.Warnf("Deployer connection did not leave IDLE state, current: %s", conn.GetState())
	}

	c.conn = conn
	c.DeploymentService = deployergrpc.NewDeploymentServiceClient(conn)
	c.TargetService = deployergrpc.NewDeploymentTargetServiceClient(conn)
	c.ConfigurationService = deployergrpc.NewTargetConfigurationServiceClient(conn)
	c.JobService = deployergrpc.NewDeploymentJobServiceClient(conn)
	c.resolved = true
	c.log.Infof("Deployer client connected via ModuleDialer (state: %s)", conn.GetState())
	return nil
}

// ListTargets lists deployment targets.
func (c *DeployerClient) ListTargets(ctx context.Context) (*deployerv1.ListTargetsResponse, error) {
	if err := c.resolve(); err != nil {
		return nil, err
	}
	rpcCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return c.TargetService.ListTargets(rpcCtx, &deployerv1.ListTargetsRequest{})
}

// ListConfigurations lists target configurations.
func (c *DeployerClient) ListConfigurations(ctx context.Context) (*deployerv1.ListConfigurationsResponse, error) {
	if err := c.resolve(); err != nil {
		return nil, err
	}
	rpcCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return c.ConfigurationService.ListConfigurations(rpcCtx, &deployerv1.ListConfigurationsRequest{})
}

// Deploy deploys a certificate to a single target configuration.
func (c *DeployerClient) Deploy(ctx context.Context, configID, certID string) (*deployerv1.DeployResponse, error) {
	if err := c.resolve(); err != nil {
		return nil, err
	}
	rpcCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return c.DeploymentService.Deploy(rpcCtx, &deployerv1.DeployRequest{
		TargetConfigurationId: configID,
		CertificateId:        certID,
	})
}

// DeployToTarget deploys a certificate to a target group.
func (c *DeployerClient) DeployToTarget(ctx context.Context, targetID, certID string) (*deployerv1.DeployToTargetResponse, error) {
	if err := c.resolve(); err != nil {
		return nil, err
	}
	triggerType := deployerv1.TriggerType_TRIGGER_TYPE_MANUAL
	rpcCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return c.DeploymentService.DeployToTarget(rpcCtx, &deployerv1.DeployToTargetRequest{
		DeploymentTargetId: targetID,
		CertificateId:      certID,
		TriggeredBy:        &triggerType,
	})
}
