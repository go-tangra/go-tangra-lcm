package store

import (
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra/v4/listquery"
)

var allLists = map[string]listquery.Spec{"certificates": CertificateList, "certificates-restricted": CertificateListRestricted, "issuers": IssuerList, "requests": RequestList, "jobs": JobList,
	"secrets": SecretList, "webhooks": WebhookList, "audit": AuditList}

func TestListSpecs(t *testing.T) {
	for name, s := range allLists {
		if err := s.Validate(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		// No sort field reaches sealed or secret material (SR-004).
		for field, f := range s.Fields {
			for _, banned := range []string{"sealed", "csr_pem", "cert_pem", "chain_pem", "details", "secret"} {
				if strings.Contains(field, banned) || strings.Contains(f.Expr, banned) {
					t.Fatalf("%s.%s sorts on %s", name, field, banned)
				}
			}
		}
	}
	if r := ListRequest(listquery.Request{}, CertificateList); r != (listquery.Request{Page: 1, PageSize: 25, Sort: "created_at", Order: listquery.Desc}) {
		t.Fatalf("zero request = %+v", r)
	}
	if r := ListRequest(listquery.Request{}, AuditList); r.PageSize != 50 || r.Sort != "ts" || r.Order != listquery.Desc {
		t.Fatalf("audit default = %+v", r)
	}
	if r := ListRequest(listquery.Request{Page: 3, PageSize: 500, Sort: "nope"}, IssuerList); r != (listquery.Request{Page: 1, PageSize: 25, Sort: "name", Order: listquery.Asc}) {
		t.Fatalf("invalid request = %+v", r)
	}
	for _, c := range []struct {
		s    listquery.Spec
		r    listquery.Request
		want string
	}{
		{CertificateList, listquery.Request{Sort: "identity", Order: listquery.Asc}, "lower(" + CertIdentityExpr + ") ASC NULLS LAST, c.id ASC"},
		{CertificateList, listquery.Request{Sort: "not_after", Order: listquery.Desc}, "c.not_after DESC, c.id DESC"},
		{CertificateList, listquery.Request{Sort: "created_at", Order: listquery.Desc}, "c.created_at DESC, c.id DESC"},
		{CertificateList, listquery.Request{Sort: "issuer", Order: listquery.Asc}, "lower(i.name) ASC NULLS LAST, c.id ASC"},
		{CertificateListRestricted, listquery.Request{Sort: "issuer", Order: listquery.Desc}, "c.issuer_id DESC, c.id DESC"},
		{IssuerList, listquery.Request{Sort: "name", Order: listquery.Desc}, "lower(i.name) DESC, i.id DESC"},
		{AuditList, listquery.Request{Sort: "ts", Order: listquery.Desc}, "a.ts DESC, a.id DESC"},
	} {
		if got := c.r.OrderBy(c.s); got != c.want {
			t.Fatalf("%s order = %s", c.r.Sort, got)
		}
	}
}

// Only tenant-wide readers sort certificates by issuer name (security review
// F-3); the specs differ in nothing else.
func TestCertificateListFor(t *testing.T) {
	if CertificateListFor(Visible{All: true}).Fields["issuer"].Expr != "i.name" {
		t.Fatal("admin issuer sort is not by name")
	}
	for _, v := range []Visible{{}, {IDs: []string{NewID()}}} {
		if CertificateListFor(v).Fields["issuer"].Expr != "c.issuer_id" {
			t.Fatalf("restricted issuer sort %+v", v)
		}
	}
	for name, f := range CertificateList.Fields {
		if g := CertificateListRestricted.Fields[name]; name != "issuer" && g != f {
			t.Fatalf("restricted %s differs", name)
		}
	}
}

func TestPageSQL(t *testing.T) {
	q := pageQuery{cols: "x", from: "t c", join: " LEFT JOIN u i ON i.id = c.u", where: "c.tenant_id = $1", key: "c.id"}
	want := "SELECT x FROM unnest(ARRAY(SELECT c.id FROM t c LEFT JOIN u i ON i.id = c.u WHERE c.tenant_id = $1 ORDER BY o LIMIT 5 OFFSET 10)) WITH ORDINALITY AS page_ids(pid, pos) " +
		"JOIN t c ON c.id = page_ids.pid ORDER BY page_ids.pos"
	if got := pageSQL(q, "o", 5, 10); got != want {
		t.Fatalf("deferred page:\n%s", got)
	}
	q.key, q.join = "", ""
	if got := pageSQL(q, "o", 5, 0); got != "SELECT x FROM t c WHERE c.tenant_id = $1 ORDER BY o LIMIT 5 OFFSET 0" {
		t.Fatalf("direct page: %s", got)
	}
	var a args
	if uuidCond("c.issuer_id", "", &a) != "" || uuidCond("c.issuer_id", "nope", &a) != " AND false" || len(a) != 0 {
		t.Fatal("uuidCond empty/invalid")
	}
	if got := uuidCond("c.issuer_id", NewID(), &a); got != " AND c.issuer_id = $1::uuid" || len(a) != 1 {
		t.Fatalf("uuidCond = %s", got)
	}
}

func TestIsUUID(t *testing.T) {
	if !IsUUID(NewID()) || IsUUID("x") || IsUUID("") || IsUUID("00000000-0000-7000-8000-0000000000000") {
		t.Fatal("IsUUID")
	}
}
