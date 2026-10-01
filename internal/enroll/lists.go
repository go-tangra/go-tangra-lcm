package enroll

import (
	"context"
	"sort"

	"github.com/go-tangra/go-tangra/v4/listquery"

	"github.com/go-tangra/go-tangra-lcm/v4/internal/authz"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/store"
)

// issuerPageSize is the batch the default-issuer scan reads issuers in.
const issuerPageSize = 200

// scope is the caller's read scope over requests and jobs as a store
// constraint, equal to the per-record checks authorizeReadRequest and
// authorizeJob(read) (go-tangra specs/032 research D5): the requester reads
// their own requests; otherwise a request (and its jobs) is readable through
// read on its pinned issuer, or on the default issuer of its SPIFFE ID's
// trust domain when it has none. Administrators read every job, and every
// request whose issuer resolves.
func (s *Service) scope(ctx context.Context, subj authz.Subjects) (store.RequestScope, error) {
	ids, all, err := s.az.ListAccessibleIDs(ctx, subj, authz.Issuer)
	if err != nil {
		return store.RequestScope{}, err
	}
	sc := store.RequestScope{Actor: subj.ActorID(), AllPinned: all, AllJobs: all}
	if !all {
		for id, ok := range ids {
			if ok {
				sc.Issuers = append(sc.Issuers, id)
			}
		}
		sort.Strings(sc.Issuers)
	}
	// The trust domains whose default issuer the caller may read (a tenant
	// has at most one default issuer per trust domain).
	after := ""
	for {
		page, lerr := s.st.ListIssuers(ctx, subj.TenantID, after, issuerPageSize)
		if lerr != nil {
			return store.RequestScope{}, lerr
		}
		for _, i := range page {
			if i.IsDefault && (all || ids[i.ID]) {
				sc.DefaultDomains = append(sc.DefaultDomains, i.TrustDomain)
			}
		}
		if len(page) < issuerPageSize {
			break
		}
		after = page[len(page)-1].Name
	}
	sort.Strings(sc.DefaultDomains)
	return sc, nil
}

// PageRequests returns one page of the requests with status (all when empty)
// the caller may read: hidden requests are neither counted nor returned.
func (s *Service) PageRequests(ctx context.Context, subj authz.Subjects, status string, req listquery.Request) (listquery.Page[RequestView], error) {
	sc, err := s.scope(ctx, subj)
	if err != nil {
		return listquery.Page[RequestView]{}, err
	}
	rows, total, applied, err := s.st.PageRequests(ctx, subj.TenantID, status, sc, req)
	if err != nil {
		return listquery.Page[RequestView]{}, err
	}
	out := make([]RequestView, 0, len(rows))
	for _, r := range rows {
		out = append(out, requestView(r))
	}
	return listquery.NewPage(out, total, applied), nil
}

// PageJobs returns one page of the jobs with status (all when empty) the
// caller may read.
func (s *Service) PageJobs(ctx context.Context, subj authz.Subjects, status string, req listquery.Request) (listquery.Page[JobView], error) {
	sc, err := s.scope(ctx, subj)
	if err != nil {
		return listquery.Page[JobView]{}, err
	}
	sc.Actor = "" // no requester exception for jobs
	rows, total, applied, err := s.st.PageJobs(ctx, subj.TenantID, status, sc, req)
	if err != nil {
		return listquery.Page[JobView]{}, err
	}
	out := make([]JobView, 0, len(rows))
	for _, j := range rows {
		out = append(out, jobView(j))
	}
	return listquery.NewPage(out, total, applied), nil
}
