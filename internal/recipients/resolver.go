// Package recipients resolves the email recipient list for LCM
// notifications by querying the portal's sys_users / sys_roles tables.
//
// Notifications are sent to:
//   - every user holding the "platform:admin" role
//   - every user holding the "lcm.admin" role
//
// Results are cached for 5 minutes so a cert-renewal storm doesn't
// hammer the DB. The cache is purely in-memory per LCM instance; with
// multiple replicas each will independently rebuild its cache, which
// is fine — the data is small and the query is cheap.
package recipients

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	_ "github.com/jackc/pgx/v5/stdlib" // postgres driver for cross-schema queries
	_ "github.com/lib/pq"              // fallback postgres driver (matches ent_client)
)

// AdminRoleCodes is the canonical list of role codes that grant access
// to certificate lifecycle events. Hardcoded because these are platform
// constants: the portal's seed SQL creates them at install time and
// they're referenced by name throughout the codebase.
var AdminRoleCodes = []string{"platform:admin", "lcm.admin"}

const defaultCacheTTL = 5 * time.Minute

// Resolver returns the union of admin emails entitled to receive LCM
// notification events. Construct one via NewResolver and inject into
// the NotificationHelper.
type Resolver struct {
	log *log.Helper
	db  *sql.DB
	ttl time.Duration

	mu        sync.RWMutex
	cached    []string
	expiresAt time.Time
}

// NewResolver opens a dedicated *sql.DB from the LCM config's database
// connection string and returns a recipient Resolver. The connection
// pool is small (a handful of conns) because lookups are short and rare.
//
// Returns nil if no database config is available — callers should
// tolerate a nil Resolver and treat it as an empty admin list.
func NewResolver(ctx *bootstrap.Context) (*Resolver, func(), error) {
	cfg := ctx.GetConfig()
	if cfg == nil || cfg.Data == nil || cfg.Data.Database == nil {
		return nil, func() {}, nil
	}
	driver := cfg.Data.Database.GetDriver()
	source := cfg.Data.Database.GetSource()
	if driver == "" || source == "" {
		return nil, func() {}, nil
	}

	// The portal uses lib/pq's "postgres" driver name; pgx registers as
	// "pgx". Map "postgres" to whichever is registered first — both
	// drivers are imported above as side-effect imports.
	if driver == "postgres" {
		// stick with "postgres" — lib/pq registers under that name
	}

	db, err := sql.Open(driver, source)
	if err != nil {
		return nil, func() {}, fmt.Errorf("open recipient resolver db: %w", err)
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)
	db.SetConnMaxIdleTime(2 * time.Minute)

	l := ctx.NewLoggerHelper("lcm/recipients")
	r := &Resolver{
		log: l,
		db:  db,
		ttl: defaultCacheTTL,
	}
	cleanup := func() {
		if err := db.Close(); err != nil {
			l.Errorf("recipient resolver db close: %v", err)
		}
	}
	return r, cleanup, nil
}

// Resolve returns the deduped lowercase email addresses of every user
// holding one of AdminRoleCodes. Results are cached for ttl; cache
// misses run a single SQL query against sys_users + sys_user_roles +
// sys_roles. On query failure the previously cached value is returned
// (stale-but-best-effort) — strict-mode notifications shouldn't go
// totally dark just because the portal DB blipped.
func (r *Resolver) Resolve(ctx context.Context) []string {
	if r == nil {
		return nil
	}
	if emails, ok := r.cached_get(); ok {
		return emails
	}

	emails, err := r.fetch(ctx)
	if err != nil {
		r.log.Errorf("Failed to query admin recipients: %v", err)
		// Fall back to whatever we last cached (may be empty); better
		// than nothing for the next caller.
		r.mu.RLock()
		stale := append([]string(nil), r.cached...)
		r.mu.RUnlock()
		return stale
	}

	r.mu.Lock()
	r.cached = emails
	r.expiresAt = time.Now().Add(r.ttl)
	r.mu.Unlock()
	return emails
}

func (r *Resolver) cached_get() ([]string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if !r.expiresAt.IsZero() && time.Now().Before(r.expiresAt) {
		out := make([]string, len(r.cached))
		copy(out, r.cached)
		return out, true
	}
	return nil, false
}

func (r *Resolver) fetch(ctx context.Context) ([]string, error) {
	const q = `
		SELECT DISTINCT lower(u.email) AS email
		  FROM sys_users u
		  JOIN sys_user_roles ur ON ur.user_id = u.id
		  JOIN sys_roles r ON r.id = ur.role_id
		 WHERE r.code = ANY($1::text[])
		   AND u.email IS NOT NULL
		   AND u.email <> ''
		   AND u.deleted_at IS NULL
		 ORDER BY email
	`
	// $1 needs to be a Postgres text[] literal. Build it as
	// {role1,role2,...}; values here are platform constants without
	// commas or curly braces so quoting is unnecessary.
	pgArray := "{" + strings.Join(AdminRoleCodes, ",") + "}"

	rows, err := r.db.QueryContext(ctx, q, pgArray)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []string
	for rows.Next() {
		var e string
		if scanErr := rows.Scan(&e); scanErr != nil {
			r.log.Warnf("scan recipient row: %v", scanErr)
			continue
		}
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		out = append(out, e)
	}
	if rowsErr := rows.Err(); rowsErr != nil {
		return nil, fmt.Errorf("rows: %w", rowsErr)
	}
	return out, nil
}
