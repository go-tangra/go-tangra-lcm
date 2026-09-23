import { z } from 'zod'
import { nonEmpty, optionalString, email, positiveInt } from '@freya/ui/forms'
import { SET_MARKER } from '@/api/types'

export const ISSUER_TYPES = ['self_signed', 'acme'] as const
export const KEY_TYPES = ['ecdsa-p256', 'ecdsa-p384', 'rsa-2048', 'rsa-4096'] as const

/** The platform DNS module provider: no credentials (mesh identity), hosted zones only. */
export const FREYA_DNS_PROVIDER = 'freya-dns'

/** An explanatory hint for DNS providers that take no credential inputs. */
export function providerHint(name: string | undefined): string {
  if (name === FREYA_DNS_PROVIDER) return 'Challenges are published through the platform DNS module; no credentials are needed. Every certificate domain must be hosted in a zone of this tenant in the DNS module.'
  return ''
}

/** A write-only secret field: blank or the stored marker means "unchanged". */
export const writeOnlySecret = optionalString(4096).transform((v) => (v === SET_MARKER ? undefined : v))

/** Issuer form. ACME fields are required only for ACME issuers; DNS credentials are validated against the provider's declared fields by the view. */
export const issuerSchema = z
  .object({
    name: nonEmpty(200),
    type: z.enum(ISSUER_TYPES),
    trust_domain: nonEmpty(253).pipe(z.string().regex(/^[a-z0-9.-]+$/i, 'Use a DNS-style trust domain (example.org).')),
    is_default: z.boolean().optional().transform((v) => v ?? false),
    key_type: z.enum(KEY_TYPES),
    validity_ceiling_days: positiveInt.pipe(z.number().min(1, 'At least 1 day.').max(3650, 'At most 3650 days.')),
    directory: optionalString(2000).pipe(z.url().optional()),
    email: optionalString(320).pipe(email.optional()),
    dns_provider: optionalString(100),
    eab_kid: optionalString(200),
    eab_hmac_key: writeOnlySecret,
    credentials: z.record(z.string(), z.string()).optional().transform((v) => v ?? {}),
  })
  .superRefine((o, ctx) => {
    if (o.type !== 'acme') return
    if (!o.directory) ctx.addIssue({ code: 'custom', path: ['directory'], message: 'The ACME directory URL is required.' })
    if (!o.email) ctx.addIssue({ code: 'custom', path: ['email'], message: 'The ACME account e-mail is required.' })
    if (!o.dns_provider) ctx.addIssue({ code: 'custom', path: ['dns_provider'], message: 'Choose the DNS provider for DNS-01 challenges.' })
  })
export type IssuerFormOutput = z.output<typeof issuerSchema>
