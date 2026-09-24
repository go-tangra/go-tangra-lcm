package authz

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-auth/sdk/v4/pkg/authclient"
	"github.com/go-tangra/go-tangra-lcm/v4/internal/store"
)

const (
	tA = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"
	tB = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c66"
	uA = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c77"
	uB = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c88"
)

// fakeStore is a minimal in-memory Store double (the real memstore is written
// by another agent). It supports FailOn to force error paths.
type fakeStore struct {
	certs   map[string]store.IssuedCertificate
	issuers map[string]store.Issuer
	grants  map[string]store.Grant
	fail    map[string]error
}

func newFake() *fakeStore {
	return &fakeStore{
		certs:   map[string]store.IssuedCertificate{},
		issuers: map[string]store.Issuer{},
		grants:  map[string]store.Grant{},
		fail:    map[string]error{},
	}
}

func (f *fakeStore) FailOn(method string, err error) { f.fail[method] = err }

func (f *fakeStore) GetCertificate(ctx context.Context, tenantID, id string) (store.IssuedCertificate, error) {
	if err := f.fail["GetCertificate"]; err != nil {
		return store.IssuedCertificate{}, err
	}
	c, ok := f.certs[id]
	if !ok || c.TenantID != tenantID {
		return store.IssuedCertificate{}, store.ErrNotFound
	}
	return c, nil
}

func (f *fakeStore) GetIssuer(ctx context.Context, tenantID, id string) (store.Issuer, error) {
	if err := f.fail["GetIssuer"]; err != nil {
		return store.Issuer{}, err
	}
	i, ok := f.issuers[id]
	if !ok || i.TenantID != tenantID {
		return store.Issuer{}, store.ErrNotFound
	}
	return i, nil
}

func (f *fakeStore) UpsertGrant(ctx context.Context, g store.Grant) (store.Grant, error) {
	if err := f.fail["UpsertGrant"]; err != nil {
		return store.Grant{}, err
	}
	// Replace any grant with the same resource/subject identity.
	for id, ex := range f.grants {
		if ex.TenantID == g.TenantID && ex.ResourceType == g.ResourceType && ex.ResourceID == g.ResourceID &&
			ex.SubjectType == g.SubjectType && ex.SubjectID == g.SubjectID {
			delete(f.grants, id)
		}
	}
	if g.GrantedAt.IsZero() {
		g.GrantedAt = time.Unix(1_600_000_000, 0)
	}
	f.grants[g.ID] = g
	return g, nil
}

func (f *fakeStore) GetGrant(ctx context.Context, tenantID, id string) (store.Grant, error) {
	if err := f.fail["GetGrant"]; err != nil {
		return store.Grant{}, err
	}
	g, ok := f.grants[id]
	if !ok || g.TenantID != tenantID {
		return store.Grant{}, store.ErrNotFound
	}
	return g, nil
}

func (f *fakeStore) DeleteGrant(ctx context.Context, tenantID, id string) error {
	if err := f.fail["DeleteGrant"]; err != nil {
		return err
	}
	g, ok := f.grants[id]
	if !ok || g.TenantID != tenantID {
		return store.ErrNotFound
	}
	delete(f.grants, id)
	return nil
}

func (f *fakeStore) GrantsOnResource(ctx context.Context, tenantID, resourceType, resourceID string) ([]store.Grant, error) {
	if err := f.fail["GrantsOnResource"]; err != nil {
		return nil, err
	}
	var out []store.Grant
	for _, g := range f.grants {
		if g.TenantID == tenantID && g.ResourceType == resourceType && g.ResourceID == resourceID {
			out = append(out, g)
		}
	}
	return out, nil
}

func (f *fakeStore) GrantsForSubjects(ctx context.Context, tenantID, userID string, roles []string, now time.Time) ([]store.Grant, error) {
	if err := f.fail["GrantsForSubjects"]; err != nil {
		return nil, err
	}
	roleSet := map[string]bool{}
	for _, r := range roles {
		roleSet[r] = true
	}
	var out []store.Grant
	for _, g := range f.grants {
		if g.TenantID != tenantID {
			continue
		}
		if g.ExpiresAt != nil && !g.ExpiresAt.After(now) {
			continue
		}
		switch g.SubjectType {
		case SubjectUser:
			if userID != "" && g.SubjectID == userID {
				out = append(out, g)
			}
		case SubjectRole:
			if roleSet[g.SubjectID] {
				out = append(out, g)
			}
		case SubjectTenant:
			out = append(out, g)
		}
	}
	return out, nil
}

func (f *fakeStore) DeleteGrantsOfResource(ctx context.Context, tenantID, resourceType, resourceID string) error {
	if err := f.fail["DeleteGrantsOfResource"]; err != nil {
		return err
	}
	for id, g := range f.grants {
		if g.TenantID == tenantID && g.ResourceType == resourceType && g.ResourceID == resourceID {
			delete(f.grants, id)
		}
	}
	return nil
}

// fixture wires an Authorizer over the fake with a frozen clock.
type fixture struct {
	fs        *fakeStore
	az        *Authorizer
	cert, iss string
	now       time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	fs := newFake()
	f := &fixture{fs: fs, az: New(fs), now: time.Unix(1_700_000_000, 0)}
	f.az.SetClock(func() time.Time { return f.now })
	f.cert, f.iss = store.NewID(), store.NewID()
	fs.certs[f.cert] = store.IssuedCertificate{ID: f.cert, TenantID: tA, SpiffeID: "spiffe://x/wl"}
	fs.issuers[f.iss] = store.Issuer{ID: f.iss, TenantID: tA, Name: "ca"}
	return f
}

func (f *fixture) grant(t *testing.T, rtype, rid, stype, sid, rel string, exp *time.Time) store.Grant {
	t.Helper()
	g, err := f.fs.UpsertGrant(context.Background(), store.Grant{ID: store.NewID(), TenantID: tA, ResourceType: rtype, ResourceID: rid, SubjectType: stype, SubjectID: sid, Relation: rel, ExpiresAt: exp})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func user(id string, roles ...string) Subjects {
	return Subjects{TenantID: tA, UserID: id, Roles: roles}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestRelationsPermissionsAndSubjects(t *testing.T) {
	for rel, want := range map[string]Permissions{
		Owner:  {Read: true, Write: true, Delete: true, Share: true, Use: true},
		Editor: {Read: true, Write: true, Use: true},
		Viewer: {Read: true},
		Sharer: {Read: true, Share: true, Use: true},
		"x":    {},
	} {
		if Of(rel) != want {
			t.Errorf("%s: %+v", rel, Of(rel))
		}
	}
	p := Of(Owner)
	for _, perm := range []string{Read, Write, Delete, Share, Use} {
		if !p.Has(perm) {
			t.Errorf("owner lacks %s", perm)
		}
	}
	// editor: read/write/use but not delete/share.
	e := Of(Editor)
	if !e.Read || !e.Write || !e.Use || e.Delete || e.Share {
		t.Fatalf("editor %+v", e)
	}
	// sharer: read/share/use but not write/delete.
	sh := Of(Sharer)
	if !sh.Read || !sh.Share || !sh.Use || sh.Write || sh.Delete {
		t.Fatalf("sharer %+v", sh)
	}
	if p.Has("fly") || !ValidPermission(Use) || ValidPermission("fly") ||
		!ValidRelation(Sharer) || ValidRelation("god") ||
		!ValidResourceType(Certificate) || !ValidResourceType(Issuer) || ValidResourceType("folder") ||
		!ValidSubjectType(SubjectTenant) || ValidSubjectType("group") {
		t.Fatal("validators")
	}
	s := SubjectsOf(authclient.Identity{TenantID: tA, UserID: uA, Roles: []string{"member", "admin"}})
	if s.TenantID != tA || s.UserID != uA || len(s.Roles) != 2 || !s.IsAdmin() || s.ActorKind() != "user" || s.ActorID() != uA {
		t.Fatalf("subjects %+v", s)
	}
	if user(uB, "member").IsAdmin() {
		t.Fatal("non-admin flagged admin")
	}
	svc := ServiceSubjects(tA, "spiffe://example.org/svc/warden")
	if svc.ActorKind() != "service" || svc.ActorID() != "spiffe://example.org/svc/warden" || svc.IsAdmin() {
		t.Fatalf("service subjects %+v", svc)
	}
}

func TestEntitlementMatrix(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	// No grant: every action forbidden; not accessible.
	for _, act := range []string{Read, Write, Delete, Share, Use} {
		if err := f.az.Check(ctx, user(uB), Certificate, f.cert, act); !errors.Is(err, ErrForbidden) {
			t.Fatalf("no grant %s: %v", act, err)
		}
	}
	ids, all, err := f.az.ListAccessibleIDs(ctx, user(uB), Certificate)
	if err != nil || all || len(ids) != 0 {
		t.Fatalf("accessible none %v %v %v", ids, all, err)
	}

	// Viewer: read only.
	vg := f.grant(t, Certificate, f.cert, SubjectUser, uB, Viewer, nil)
	assertActions(t, f.az, user(uB), Certificate, f.cert, map[string]bool{Read: true, Write: false, Delete: false, Share: false, Use: false})
	ids, _, _ = f.az.ListAccessibleIDs(ctx, user(uB), Certificate)
	if !ids[f.cert] {
		t.Fatal("viewer resource not accessible")
	}

	// Editor via role: read/write/use, not delete/share.
	must(t, f.fs.DeleteGrant(ctx, tA, vg.ID))
	f.grant(t, Certificate, f.cert, SubjectRole, "ops", Editor, nil)
	assertActions(t, f.az, user(uB, "ops"), Certificate, f.cert, map[string]bool{Read: true, Write: true, Use: true, Delete: false, Share: false})

	// Sharer via tenant-wide grant on the issuer: read/share/use.
	f.grant(t, Issuer, f.iss, SubjectTenant, "", Sharer, nil)
	assertActions(t, f.az, user(uB), Issuer, f.iss, map[string]bool{Read: true, Share: true, Use: true, Write: false, Delete: false})

	// Owner: all.
	f.grant(t, Issuer, f.iss, SubjectUser, uA, Owner, nil)
	assertActions(t, f.az, user(uA), Issuer, f.iss, map[string]bool{Read: true, Write: true, Delete: true, Share: true, Use: true})

	// Admin role holds owner implicitly on everything.
	assertActions(t, f.az, user(uB, "admin"), Certificate, f.cert, map[string]bool{Read: true, Write: true, Delete: true, Share: true, Use: true})
	if _, all, _ := f.az.ListAccessibleIDs(ctx, user(uB, "owner"), Certificate); !all {
		t.Fatal("admin accessible-all")
	}

	// Effective reports strongest relation and contributing grants (union + rank).
	f.grant(t, Certificate, f.cert, SubjectUser, uB, Viewer, nil)   // weaker, after the editor role grant
	f.grant(t, Certificate, f.cert, SubjectTenant, "", Sharer, nil) // weaker than editor: no rank bump
	perms, rel, srcs, err := f.az.Effective(ctx, user(uB, "ops"), Certificate, f.cert)
	if err != nil || rel != Editor || !perms.Write || !perms.Share || perms.Delete || len(srcs) != 3 {
		t.Fatalf("effective %+v %s %d %v", perms, rel, len(srcs), err)
	}
}

func assertActions(t *testing.T, az *Authorizer, s Subjects, rtype, rid string, want map[string]bool) {
	t.Helper()
	ctx := context.Background()
	for act, ok := range want {
		err := az.Check(ctx, s, rtype, rid, act)
		if ok && err != nil {
			t.Fatalf("%s expected allowed: %v", act, err)
		}
		if !ok && !errors.Is(err, ErrForbidden) {
			t.Fatalf("%s expected forbidden: %v", act, err)
		}
	}
}

func TestExpiryAndScoping(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	// Expired grant ignored; boundary counts as expired; future grant applies.
	past := f.now.Add(-time.Second)
	f.grant(t, Certificate, f.cert, SubjectUser, uB, Owner, &past)
	if err := f.az.Check(ctx, user(uB), Certificate, f.cert, Read); !errors.Is(err, ErrForbidden) {
		t.Fatalf("expired grant applied: %v", err)
	}
	edge := f.now
	f.grant(t, Certificate, f.cert, SubjectUser, uB, Owner, &edge)
	if err := f.az.Check(ctx, user(uB), Certificate, f.cert, Read); !errors.Is(err, ErrForbidden) {
		t.Fatalf("boundary grant applied: %v", err)
	}
	future := f.now.Add(time.Hour)
	f.grant(t, Certificate, f.cert, SubjectUser, uB, Owner, &future)
	if err := f.az.Check(ctx, user(uB), Certificate, f.cert, Delete); err != nil {
		t.Fatalf("future grant ignored: %v", err)
	}

	// Service subjects see tenant grants only.
	f.grant(t, Issuer, f.iss, SubjectTenant, "", Editor, nil)
	svc := ServiceSubjects(tA, "spiffe://example.org/svc/warden")
	if err := f.az.Check(ctx, svc, Issuer, f.iss, Use); err != nil {
		t.Fatalf("service tenant grant: %v", err)
	}
	if err := f.az.Check(ctx, svc, Certificate, f.cert, Use); !errors.Is(err, ErrForbidden) {
		t.Fatalf("service saw a user grant: %v", err)
	}

	// Cross-tenant and unknown resources are ErrNotFound; bad input ErrInput.
	if err := f.az.Check(ctx, Subjects{TenantID: tB, UserID: uB}, Certificate, f.cert, Read); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross tenant: %v", err)
	}
	if err := f.az.Check(ctx, user(uB), Certificate, store.NewID(), Read); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown resource: %v", err)
	}
	if err := f.az.Check(ctx, user(uB), "folder", f.cert, Read); !errors.Is(err, ErrInput) {
		t.Fatalf("bad type: %v", err)
	}
	if err := f.az.Check(ctx, user(uB), Certificate, f.cert, "fly"); !errors.Is(err, ErrInput) {
		t.Fatalf("bad action: %v", err)
	}
}

func TestEffectiveAndAccessibleErrors(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, _, _, err := f.az.Effective(ctx, user(uB), "folder", f.cert); !errors.Is(err, ErrInput) {
		t.Fatalf("effective bad type: %v", err)
	}
	if _, _, _, err := f.az.Effective(ctx, user(uB), Certificate, store.NewID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("effective missing: %v", err)
	}
	if _, _, err := f.az.ListAccessibleIDs(ctx, user(uB), "folder"); !errors.Is(err, ErrInput) {
		t.Fatalf("accessible bad type: %v", err)
	}
	// Store failures propagate.
	f.fs.FailOn("GrantsOnResource", errors.New("db"))
	if err := f.az.Check(ctx, user(uB), Certificate, f.cert, Read); err == nil {
		t.Fatal("check db error swallowed")
	}
	if _, _, _, err := f.az.Effective(ctx, user(uB), Certificate, f.cert); err == nil {
		t.Fatal("effective db error swallowed")
	}
	f.fs.FailOn("GrantsOnResource", nil)
	f.fs.FailOn("GrantsForSubjects", errors.New("db"))
	if _, _, err := f.az.ListAccessibleIDs(ctx, user(uB), Certificate); err == nil {
		t.Fatal("accessible db error swallowed")
	}
	f.fs.FailOn("GrantsForSubjects", nil)
	// locate db error is not masked as ErrNotFound (issuer path too).
	f.fs.FailOn("GetIssuer", errors.New("db"))
	if err := f.az.Check(ctx, user(uB), Issuer, f.iss, Read); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("locate db error: %v", err)
	}
	f.fs.FailOn("GetIssuer", nil)
}

func TestGrantRevoke(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	must(t, f.az.GrantOwner(ctx, tA, Certificate, f.cert, uA))
	must(t, f.az.GrantOwner(ctx, tA, Certificate, f.cert, "")) // service creator: no grant
	owner := user(uA)
	if err := f.az.Check(ctx, owner, Certificate, f.cert, Delete); err != nil {
		t.Fatalf("creator not owner: %v", err)
	}

	exp := f.now.Add(time.Hour)
	g1, err := f.az.Grant(ctx, owner, GrantInput{ResourceType: Certificate, ResourceID: f.cert, SubjectType: SubjectRole, SubjectID: "ops", Relation: Sharer})
	must(t, err)
	g2, err := f.az.Grant(ctx, owner, GrantInput{ResourceType: Certificate, ResourceID: f.cert, SubjectType: SubjectUser, SubjectID: uB, Relation: Viewer, ExpiresAt: &exp})
	must(t, err)
	if g1.Relation != Sharer || g2.ExpiresAt == nil || g2.GrantedBy == nil || *g2.GrantedBy != uA {
		t.Fatalf("grant views %+v %+v", g1, g2)
	}

	// Above-granter: a sharer may grant viewer/sharer but not editor/owner.
	sharer := user(store.NewID(), "ops")
	if _, err := f.az.Grant(ctx, sharer, GrantInput{ResourceType: Certificate, ResourceID: f.cert, SubjectType: SubjectUser, SubjectID: store.NewID(), Relation: Viewer}); err != nil {
		t.Fatalf("sharer grants viewer: %v", err)
	}
	if _, err := f.az.Grant(ctx, sharer, GrantInput{ResourceType: Certificate, ResourceID: f.cert, SubjectType: SubjectUser, SubjectID: store.NewID(), Relation: Owner}); !errors.Is(err, ErrAboveGranter) {
		t.Fatalf("sharer grants owner: %v", err)
	}
	// Viewer (no share) cannot grant at all.
	if _, err := f.az.Grant(ctx, user(uB), GrantInput{ResourceType: Certificate, ResourceID: f.cert, SubjectType: SubjectUser, SubjectID: store.NewID(), Relation: Viewer}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("viewer grants: %v", err)
	}

	// Bad input shapes.
	for _, in := range []GrantInput{
		{ResourceType: "folder", ResourceID: f.cert, SubjectType: SubjectUser, SubjectID: uB, Relation: Viewer},
		{ResourceType: Certificate, ResourceID: f.cert, SubjectType: SubjectTenant, SubjectID: "x", Relation: Viewer},
		{ResourceType: Certificate, ResourceID: f.cert, SubjectType: SubjectUser, SubjectID: "", Relation: Viewer},
		{ResourceType: Certificate, ResourceID: f.cert, SubjectType: "group", SubjectID: uB, Relation: Viewer},
		{ResourceType: Certificate, ResourceID: f.cert, SubjectType: SubjectUser, SubjectID: uB, Relation: "god"},
		{ResourceType: Certificate, ResourceID: "", SubjectType: SubjectUser, SubjectID: uB, Relation: Viewer},
	} {
		if _, err := f.az.Grant(ctx, owner, in); !errors.Is(err, ErrInput) {
			t.Errorf("bad input %+v: %v", in, err)
		}
	}
	past := f.now.Add(-time.Minute)
	if _, err := f.az.Grant(ctx, owner, GrantInput{ResourceType: Certificate, ResourceID: f.cert, SubjectType: SubjectUser, SubjectID: uB, Relation: Viewer, ExpiresAt: &past}); !errors.Is(err, ErrInput) {
		t.Fatalf("past expiry: %v", err)
	}
	if _, err := f.az.Grant(ctx, owner, GrantInput{ResourceType: Certificate, ResourceID: store.NewID(), SubjectType: SubjectUser, SubjectID: uB, Relation: Viewer}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing resource: %v", err)
	}

	// Service granter leaves no granted_by.
	f.grant(t, Issuer, f.iss, SubjectTenant, "", Sharer, nil)
	svc := ServiceSubjects(tA, "spiffe://example.org/svc/warden")
	sg, err := f.az.Grant(ctx, svc, GrantInput{ResourceType: Issuer, ResourceID: f.iss, SubjectType: SubjectUser, SubjectID: uB, Relation: Viewer})
	if err != nil || sg.GrantedBy != nil {
		t.Fatalf("service grant %+v %v", sg, err)
	}

	// Revoke: needs share; unknown id not found; effective on next check.
	if err := f.az.Revoke(ctx, user(uB), g1.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("revoke without share: %v", err)
	}
	if err := f.az.Revoke(ctx, owner, store.NewID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoke unknown: %v", err)
	}
	must(t, f.az.Revoke(ctx, owner, g1.ID))
	if err := f.az.Check(ctx, sharer, Certificate, f.cert, Use); !errors.Is(err, ErrForbidden) {
		t.Fatalf("revoked grant still applies: %v", err)
	}

	// DropResource clears every grant on the resource.
	must(t, f.az.DropResource(ctx, tA, Certificate, f.cert))
	if gs, _ := f.fs.GrantsOnResource(ctx, tA, Certificate, f.cert); len(gs) != 0 {
		t.Fatalf("grants left after drop: %d", len(gs))
	}
}

func TestGrantRevokeStoreErrors(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	must(t, f.az.GrantOwner(ctx, tA, Certificate, f.cert, uA))
	owner := user(uA)
	g, err := f.az.Grant(ctx, owner, GrantInput{ResourceType: Certificate, ResourceID: f.cert, SubjectType: SubjectUser, SubjectID: uB, Relation: Viewer})
	must(t, err)

	// GrantOwner and Grant surface UpsertGrant failures.
	f.fs.FailOn("UpsertGrant", errors.New("db"))
	if err := f.az.GrantOwner(ctx, tA, Certificate, f.cert, uA); err == nil {
		t.Fatal("grant-owner upsert error swallowed")
	}
	if _, err := f.az.Grant(ctx, owner, GrantInput{ResourceType: Certificate, ResourceID: f.cert, SubjectType: SubjectUser, SubjectID: uB, Relation: Viewer}); err == nil {
		t.Fatal("grant upsert error swallowed")
	}
	f.fs.FailOn("UpsertGrant", nil)

	// Grant with a resolve (locate) error propagates.
	f.fs.FailOn("GetCertificate", errors.New("db"))
	if _, err := f.az.Grant(ctx, owner, GrantInput{ResourceType: Certificate, ResourceID: f.cert, SubjectType: SubjectUser, SubjectID: uB, Relation: Viewer}); err == nil {
		t.Fatal("grant locate error swallowed")
	}
	f.fs.FailOn("GetCertificate", nil)

	// Revoke: GetGrant error, resolve error, DeleteGrant error.
	f.fs.FailOn("GetGrant", errors.New("db"))
	if err := f.az.Revoke(ctx, owner, g.ID); err == nil {
		t.Fatal("revoke get-grant error swallowed")
	}
	f.fs.FailOn("GetGrant", nil)
	f.fs.FailOn("GrantsOnResource", errors.New("db"))
	if err := f.az.Revoke(ctx, owner, g.ID); err == nil {
		t.Fatal("revoke resolve error swallowed")
	}
	f.fs.FailOn("GrantsOnResource", nil)
	f.fs.FailOn("DeleteGrant", errors.New("db"))
	if err := f.az.Revoke(ctx, owner, g.ID); err == nil {
		t.Fatal("revoke delete error swallowed")
	}
	f.fs.FailOn("DeleteGrant", nil)

	// DropResource surfaces its store error.
	f.fs.FailOn("DeleteGrantsOfResource", errors.New("db"))
	if err := f.az.DropResource(ctx, tA, Certificate, f.cert); err == nil {
		t.Fatal("drop error swallowed")
	}
	f.fs.FailOn("DeleteGrantsOfResource", nil)
}

func TestNotFoundHelper(t *testing.T) {
	if !errors.Is(notFound(store.ErrNotFound), ErrNotFound) || notFound(nil) != nil {
		t.Fatal("notFound mapping")
	}
	other := errors.New("x")
	if !errors.Is(notFound(other), other) {
		t.Fatal("notFound passthrough")
	}
}

func TestDefaultClock(t *testing.T) {
	// New wires a real clock; exercise it so the default is covered.
	az := New(newFake())
	if err := az.Check(context.Background(), user(uB), Certificate, store.NewID(), Read); !errors.Is(err, ErrNotFound) {
		t.Fatalf("default clock: %v", err)
	}
}
