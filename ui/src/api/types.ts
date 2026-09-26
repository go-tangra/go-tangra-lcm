// Domain types mirroring the lcm OpenAPI contract (api/openapi/lcm.yaml).
export type IssuerType = 'self_signed' | 'acme'
export type CertificateKind = 'svid' | 'generic'
export type CertificateStatus = 'active' | 'expiring' | 'expired' | 'revoked'
export type RequestStatus = 'pending' | 'approved' | 'rejected' | 'issued' | 'processing' | 'failed'
export type JobStatus = 'queued' | 'processing' | 'completed' | 'failed'
export type SecretKind = 'acme_account' | 'dns_credential'
export type DeploymentKind = 'file' | 'pull' | 'webhook'
export type Relation = 'owner' | 'editor' | 'viewer' | 'sharer'
export type ResourceType = 'certificate' | 'issuer'
export type SubjectType = 'user' | 'role' | 'tenant'

export interface Permissions {
  read?: boolean
  write?: boolean
  delete?: boolean
  share?: boolean
  use?: boolean
}

export interface Page<T> {
  items: T[]
  next_cursor?: string
}

export type Settings = Record<string, unknown>

// ---- issuers ----
export interface Issuer {
  id: string
  name: string
  type: IssuerType
  trust_domain: string
  is_default?: boolean
  enabled?: boolean
  settings: Settings
  certificate_count?: number
  created_by?: string
  created_at?: string
  permissions?: Permissions
}

export interface IssuerInput {
  name: string
  type: IssuerType
  trust_domain: string
  is_default?: boolean
  settings?: Settings
  secrets?: Record<string, unknown>
}

export interface DnsProviderField {
  key: string
  label: string
  secret: boolean
  required: boolean
}

export interface DnsProvider {
  name: string
  display_name: string
  fields: DnsProviderField[]
}

// ---- certificates ----
export interface Certificate {
  id: string
  serial?: string
  spiffe_id: string
  subject?: string
  issuer_id?: string
  sans?: string[]
  not_before?: string
  not_after?: string
  fingerprint_sha256?: string
  kind?: CertificateKind
  has_key?: boolean
  auto_renew?: boolean
  status: CertificateStatus
  owner?: string
  labels?: Record<string, string>
  created_at?: string
  permissions?: Permissions
}

export interface CertificateBundle {
  certificate: Certificate
  cert_pem?: string
  chain_pem?: string
  bundle_pem?: string
  key_pem?: string
}

export interface IssueInput {
  issuer_id?: string | undefined
  spiffe_id: string
  csr_pem?: string | undefined
  subject?: string | undefined
  dns_sans?: string[] | undefined
  validity_seconds?: number | undefined
  deliver_key?: boolean | undefined
}

export interface AcmeInput {
  issuer_id: string
  domains: string[]
  csr_pem?: string | undefined
  deliver_key?: boolean | undefined
  auto_renew?: boolean | undefined
}

export interface CertificateFilter {
  issuer_id?: string | undefined
  spiffe_id?: string | undefined
  status?: CertificateStatus | undefined
}

export interface CertificateUpdate {
  owner?: string | undefined
  labels?: Record<string, string> | undefined
  auto_renew?: boolean | undefined
}

// ---- requests & jobs ----
/** A certificate request; an ACME order is kind "generic" (domains in sans, no SPIFFE id). */
export interface CertRequest {
  id: string
  kind?: CertificateKind
  spiffe_id: string
  sans?: string[]
  subject?: string
  issuer_id?: string
  status: RequestStatus
  requested_by?: string
  reviewed_by?: string
  certificate_id?: string | null
  reason?: string
  created_at?: string
  updated_at?: string
}

export interface Job {
  id: string
  type?: string
  status: JobStatus
  certificate_id?: string | null
  request_id?: string | null
  attempts?: number
  error?: string
  created_at?: string
  updated_at?: string
}

// ---- secrets & webhooks ----
export interface Secret {
  id: string
  name: string
  kind: SecretKind
  in_use?: boolean
  created_by?: string
  created_at?: string
  updated_at?: string
}

export interface SecretInput {
  name: string
  kind: SecretKind
  value: Record<string, unknown>
}

export interface Webhook {
  id: string
  name: string
  url: string
  event_types: string[]
  created_by?: string
  created_at?: string
}

export interface WebhookInput {
  name: string
  url: string
  event_types: string[]
  secret?: string
}

export interface DeploymentTarget {
  id: string
  name: string
  kind: DeploymentKind
  config?: Settings
  created_at?: string
}

// ---- permissions ----
export interface Grant {
  id: string
  resource_type: ResourceType
  resource_id: string
  subject_type: SubjectType
  subject_id?: string
  relation: Relation
  granted_by?: string
  granted_at?: string
  expires_at?: string | null
  expired?: boolean
}

export interface Source {
  id?: string
  resource_type: ResourceType
  resource_id: string
  subject_type: SubjectType
  subject_id?: string
  relation: Relation
  expires_at?: string | null
}

export interface Effective {
  relation: string
  permissions: Permissions
  grants: Source[]
}

export interface GrantInput {
  resource_type: ResourceType
  resource_id: string
  subject_type: SubjectType
  subject_id?: string | undefined
  relation: Relation
  expires_at?: string | null | undefined
}

// ---- stats & audit ----
export interface Stats {
  certificates: Record<string, number>
  issuers: number
  jobs: Record<string, number>
  clients: number
  expiring_soon: number
  recent_errors: number
  open_streams: number
}

export interface AuditItem {
  ts: string
  event_type: string
  actor_kind: string
  actor_id?: string
  subject_kind?: string
  subject_id?: string
  subject_name?: string
  outcome: string
  reason?: string
  details: Record<string, unknown>
}

export interface AuditFilter {
  event_type?: string | undefined
  actor_id?: string | undefined
  from?: string | undefined
  to?: string | undefined
}

// ---- backup ----
export interface EntityReport {
  created: number
  skipped: number
  overwritten: number
  failed: number
}

export interface BackupReport {
  issuers: EntityReport
  certificates: EntityReport
  secrets: EntityReport
  webhooks: EntityReport
  warnings: string[]
}

// ---- auth directory ----
export interface UserHit {
  id: string
  display_name: string
  avatar_url?: string
  email?: string
}

export interface RoleHit {
  slug: string
  display_name: string
}

/** Relations a granter holding `held` may hand out (never above their own). */
export function grantable(held: string): Relation[] {
  const order: Relation[] = ['viewer', 'sharer', 'editor', 'owner']
  const rank = order.indexOf(held as Relation)
  return rank < 0 ? [] : order.slice(0, rank + 1)
}

/** The marker a write-only secret field shows when a value is already stored. */
export const SET_MARKER = '__set__'
