package issue

import (
	"context"
	"sort"

	"github.com/go-tangra/go-tangra/v4/listquery"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/authz"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/store"
)

// CertificateListFilter selects certificates for a list page.
type CertificateListFilter struct {
	IssuerID string
	SpiffeID string
	Status   string
}

// Readable is the caller's read scope over a resource type as a store
// constraint: tenant administrators are unrestricted, everyone else sees
// exactly the ids they hold a read grant on (go-tangra specs/032 research D5:
// the same set constrains the count and the page).
func Readable(ctx context.Context, az *authz.Authorizer, subj authz.Subjects, resourceType string) (store.Visible, error) {
	ids, all, err := az.ListAccessibleIDs(ctx, subj, resourceType)
	if err != nil {
		return store.Visible{}, err
	}
	if all {
		return store.Visible{All: true}, nil
	}
	out := make([]string, 0, len(ids))
	for id, ok := range ids {
		if ok {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return store.Visible{IDs: out}, nil
}

// PageCertificates returns one page of the certificates the caller may read
// matching f: hidden certificates are neither counted nor returned.
func (s *Service) PageCertificates(ctx context.Context, subj authz.Subjects, f CertificateListFilter, req listquery.Request) (listquery.Page[CertificateView], error) {
	vis, err := Readable(ctx, s.az, subj, authz.Certificate)
	if err != nil {
		return listquery.Page[CertificateView]{}, err
	}
	rows, total, applied, err := s.st.PageCertificates(ctx, subj.TenantID, store.CertificatePageFilter{IssuerID: f.IssuerID, SpiffeID: f.SpiffeID, Status: f.Status, Visible: vis}, req)
	if err != nil {
		return listquery.Page[CertificateView]{}, err
	}
	out := make([]CertificateView, 0, len(rows))
	for _, row := range rows {
		perms, _, _, perr := s.az.Effective(ctx, subj, authz.Certificate, row.ID)
		if perr != nil {
			return listquery.Page[CertificateView]{}, perr
		}
		out = append(out, s.certView(row, perms))
	}
	return listquery.NewPage(out, total, applied), nil
}

// PageIssuers returns one page of the issuers the caller may read.
func (s *Service) PageIssuers(ctx context.Context, subj authz.Subjects, req listquery.Request) (listquery.Page[IssuerView], error) {
	vis, err := Readable(ctx, s.az, subj, authz.Issuer)
	if err != nil {
		return listquery.Page[IssuerView]{}, err
	}
	rows, total, applied, err := s.st.PageIssuers(ctx, subj.TenantID, vis, req)
	if err != nil {
		return listquery.Page[IssuerView]{}, err
	}
	out := make([]IssuerView, 0, len(rows))
	for _, row := range rows {
		perms, _, _, perr := s.az.Effective(ctx, subj, authz.Issuer, row.ID)
		if perr != nil {
			return listquery.Page[IssuerView]{}, perr
		}
		out = append(out, issuerView(row, perms))
	}
	return listquery.NewPage(out, total, applied), nil
}
