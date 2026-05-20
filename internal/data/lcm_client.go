package data

import (
	"context"
	"encoding/json"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	entCrud "github.com/tx7do/go-crud/entgo"

	"github.com/go-tangra/go-tangra-lcm/internal/data/ent"
	"github.com/go-tangra/go-tangra-lcm/internal/data/ent/lcmclient"

	lcmV1 "github.com/go-tangra/go-tangra-lcm/gen/go/lcm/service/v1"
)

type LcmClientRepo struct {
	entClient *entCrud.EntClient[*ent.Client]
	log       *log.Helper
}

func NewLcmClientRepo(ctx *bootstrap.Context, entClient *entCrud.EntClient[*ent.Client]) *LcmClientRepo {
	return &LcmClientRepo{
		log:       ctx.NewLoggerHelper("lcm_client/repo"),
		entClient: entClient,
	}
}

// GetByClientID retrieves a client by its client_id (legacy - for backward compatibility)
func (r *LcmClientRepo) GetByClientID(ctx context.Context, clientID string) (*ent.LcmClient, error) {
	entity, err := r.entClient.Client().LcmClient.Query().
		Where(lcmclient.ClientIDEQ(clientID)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil // Not found is not an error
		}
		r.log.Errorf("query client failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("query client failed")
	}
	return entity, nil
}

// GetByTenantAndClientID retrieves a client by tenant_id and client_id
func (r *LcmClientRepo) GetByTenantAndClientID(ctx context.Context, tenantID uint32, clientID string) (*ent.LcmClient, error) {
	entity, err := r.entClient.Client().LcmClient.Query().
		Where(
			lcmclient.TenantIDEQ(tenantID),
			lcmclient.ClientIDEQ(clientID),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil // Not found is not an error
		}
		r.log.Errorf("query client failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("query client failed")
	}
	return entity, nil
}

// Create creates a new LcmClient with tenant
func (r *LcmClientRepo) Create(ctx context.Context, tenantID uint32, clientID string, metadata map[string]string) (*ent.LcmClient, error) {
	builder := r.entClient.Client().LcmClient.Create().
		SetTenantID(tenantID).
		SetClientID(clientID).
		SetStatus(lcmclient.StatusLCM_CLIENT_ACTIVE).
		SetCreateTime(time.Now())

	if len(metadata) > 0 {
		builder.SetMetadata(metadata)
	}

	entity, err := builder.Save(ctx)
	if err != nil {
		r.log.Errorf("create client failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("create client failed")
	}

	return entity, nil
}

// Update updates an existing LcmClient
func (r *LcmClientRepo) Update(ctx context.Context, id uint32, metadata map[string]string) (*ent.LcmClient, error) {
	builder := r.entClient.Client().LcmClient.UpdateOneID(id).
		SetUpdateTime(time.Now())

	if len(metadata) > 0 {
		builder.SetMetadata(metadata)
	}

	entity, err := builder.Save(ctx)
	if err != nil {
		r.log.Errorf("update client failed: %s", err.Error())
		return nil, lcmV1.ErrorInternalServerError("update client failed")
	}

	return entity, nil
}

// LcmClientListFilter narrows a ListByFilter query.
type LcmClientListFilter struct {
	TenantID *uint32
	Status   *lcmclient.Status
	// Labels is matched against the JSON metadata field using postgres
	// jsonb containment (@>). All key/value pairs must be present in the
	// stored metadata for the client to match.
	Labels   map[string]string
	Page     uint32
	PageSize uint32
}

// ListByFilter returns clients matching the filter and the total count.
// When PageSize is zero, all matching rows are returned (no pagination).
func (r *LcmClientRepo) ListByFilter(ctx context.Context, filter LcmClientListFilter) ([]*ent.LcmClient, int, error) {
	builder := r.entClient.Client().LcmClient.Query()

	if filter.TenantID != nil {
		builder = builder.Where(lcmclient.TenantIDEQ(*filter.TenantID))
	}
	if filter.Status != nil {
		builder = builder.Where(lcmclient.StatusEQ(*filter.Status))
	}
	if len(filter.Labels) > 0 {
		labelJSON, err := json.Marshal(filter.Labels)
		if err != nil {
			return nil, 0, lcmV1.ErrorInternalServerError("encode label filter failed")
		}
		// PostgreSQL jsonb @> operator: stored metadata must contain all
		// supplied key/value pairs.
		builder.Modify(func(s *sql.Selector) {
			s.Where(sql.ExprP(s.C(lcmclient.FieldMetadata)+" @> ?", string(labelJSON)))
		})
	}

	total, err := builder.Count(ctx)
	if err != nil {
		r.log.Errorf("count clients failed: %s", err.Error())
		return nil, 0, lcmV1.ErrorInternalServerError("count clients failed")
	}

	if filter.PageSize > 0 {
		builder = builder.Limit(int(filter.PageSize))
		if filter.Page > 1 {
			builder = builder.Offset(int((filter.Page - 1) * filter.PageSize))
		}
	}

	rows, err := builder.All(ctx)
	if err != nil {
		r.log.Errorf("list clients failed: %s", err.Error())
		return nil, 0, lcmV1.ErrorInternalServerError("list clients failed")
	}
	return rows, total, nil
}

// ToProto converts an ent.LcmClient to lcmV1.LcmClient
func (r *LcmClientRepo) ToProto(entity *ent.LcmClient) *lcmV1.LcmClient {
	if entity == nil {
		return nil
	}

	proto := &lcmV1.LcmClient{
		Id:       &entity.ID,
		ClientId: &entity.ClientID,
		TenantId: entity.TenantID,
		Metadata: entity.Metadata,
	}

	if entity.Description != "" {
		proto.Description = &entity.Description
	}
	if entity.ContactEmail != "" {
		proto.ContactEmail = &entity.ContactEmail
	}
	if entity.Organization != "" {
		proto.Organization = &entity.Organization
	}

	return proto
}
