package store

import (
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra/v4/listquery"
)

var allLists = map[string]listquery.Spec{"certificates": CertificateList, "issuers": IssuerList, "requests": RequestList, "jobs": JobList,
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
		{CertificateList, listquery.Request{Sort: "not_after", Order: listquery.Desc}, "c.not_after DESC NULLS LAST, c.id DESC"},
		{AuditList, listquery.Request{Sort: "ts", Order: listquery.Desc}, "a.ts DESC NULLS LAST, a.id DESC"},
	} {
		if got := c.r.OrderBy(c.s); got != c.want {
			t.Fatalf("%s order = %s", c.r.Sort, got)
		}
	}
}

func TestIsUUID(t *testing.T) {
	if !IsUUID(NewID()) || IsUUID("x") || IsUUID("") || IsUUID("00000000-0000-7000-8000-0000000000000") {
		t.Fatal("IsUUID")
	}
}
