package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/tx7do/go-crud/entgo/mixin"
)

// ClientInstalledCertificate records the state of a certificate that a
// tangra-client agent has applied locally (e.g. installed into nginx). The
// agent calls ReportInstalledCertificate after install/refresh; the deployer
// reads from this table via ListClientInstalledCertificates to verify that a
// push actually landed.
//
// Unique key: (tenant_id, client_id, name). "name" is the logical certificate
// identifier used by the agent under live/<name>/ — usually the CommonName
// or the deployer's cert_name override.
type ClientInstalledCertificate struct {
	ent.Schema
}

func (ClientInstalledCertificate) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "client_installed_certificates"},
		entsql.WithComments(true),
	}
}

func (ClientInstalledCertificate) Fields() []ent.Field {
	return []ent.Field{
		field.String("client_id").
			NotEmpty().
			Comment("Logical client identifier (matches LcmClient.client_id)"),

		field.String("name").
			NotEmpty().
			Comment("Certificate name on the agent (e.g. CN or pusher override)"),

		field.String("serial_number").
			Optional().
			Comment("Serial number of the installed certificate"),

		field.String("fingerprint_sha256").
			Optional().
			Comment("SHA256 fingerprint of the installed certificate"),

		field.Enum("status").
			Values(
				"INSTALLED_CERT_STATUS_UNSPECIFIED",
				"INSTALLED_CERT_STATUS_INSTALLED",
				"INSTALLED_CERT_STATUS_FAILED",
				"INSTALLED_CERT_STATUS_REMOVED",
			).
			Default("INSTALLED_CERT_STATUS_UNSPECIFIED").
			Comment("Last reported status from the agent"),

		field.String("message").
			Optional().
			Comment("Free-form message from the agent (error text on failures)"),

		field.Time("installed_at").
			Optional().
			Nillable().
			Comment("When the agent applied this certificate"),
	}
}

func (ClientInstalledCertificate) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.AutoIncrementId{},
		mixin.Time{},
		mixin.TenantID[uint32]{},
	}
}

func (ClientInstalledCertificate) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id", "client_id", "name").Unique(),
		index.Fields("tenant_id", "client_id"),
		index.Fields("serial_number"),
	}
}
