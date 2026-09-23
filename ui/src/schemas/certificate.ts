import { z } from 'zod'
import { nonEmpty, optionalString, positiveInt } from '@freya/ui/forms'

export const CERTIFICATE_STATUSES = ['active', 'expiring', 'expired', 'revoked'] as const

const csvList = (max: number) => z.string().nullish().transform((s) => (s ?? '').split(',').map((x) => x.trim()).filter(Boolean)).pipe(z.array(z.string().max(253)).max(max))
const pem = optionalString(65536).pipe(z.string().regex(/^-----BEGIN [A-Z ]+-----/, 'Paste a PEM block (-----BEGIN …-----).').optional())

/** Mesh SVID issuance (POST /certificates/issue). */
export const issueSvidSchema = z.object({
  issuer_id: optionalString(64),
  spiffe_id: nonEmpty(2048).pipe(z.string().regex(/^spiffe:\/\/[^/\s]+\/\S+$/, 'Use a SPIFFE ID (spiffe://trust-domain/path).')),
  subject: optionalString(500),
  dns_sans: csvList(50),
  validity_days: positiveInt.pipe(z.number().max(3650)),
  csr_pem: pem,
})
export type IssueSvidOutput = z.output<typeof issueSvidSchema>

/** ACME / public certificate (POST /certificates/acme). */
export const issueAcmeSchema = z.object({
  issuer_id: nonEmpty(64),
  domains: csvList(100).pipe(z.array(z.string().regex(/^(\*\.)?[a-z0-9-]+(\.[a-z0-9-]+)+$/i, 'Enter valid domain names.')).min(1, 'Enter at least one domain.')),
  auto_renew: z.boolean().optional().transform((v) => v ?? true),
  csr_pem: pem,
})
export type IssueAcmeOutput = z.output<typeof issueAcmeSchema>

export const revokeSchema = z.object({ reason: optionalString(500) })

export const certificateFilterSchema = z.object({
  status: z.enum(CERTIFICATE_STATUSES).optional(),
  issuer_id: z.string().optional(),
  spiffe_id: z.string().trim().max(2048).optional(),
})
