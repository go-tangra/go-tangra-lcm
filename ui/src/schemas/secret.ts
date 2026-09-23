import { z } from 'zod'
import { nonEmpty, jsonObject, optionalString, email } from '@freya/ui/forms'

export const SECRET_KINDS = ['acme_account', 'dns_credential'] as const

/** Tenant secret: the value is write-only (JSON object or a bare string wrapped as {value}). */
export const secretSchema = z.object({
  name: nonEmpty(200),
  kind: z.enum(SECRET_KINDS),
  value: z.string().nullish().transform((raw, ctx) => {
    const t = (raw ?? '').trim()
    if (!t) return {} as Record<string, unknown>
    if (!t.startsWith('{')) return { value: t }
    const r = jsonObject.safeParse(t)
    if (!r.success) {
      ctx.addIssue({ code: 'custom', message: r.error.issues[0]?.message ?? 'Enter valid JSON.' })
      return z.NEVER
    }
    return r.data
  }),
})
export type SecretFormOutput = z.output<typeof secretSchema>

/** Outbound webhook; the signing secret is write-only. */
export const webhookSchema = z.object({
  name: nonEmpty(200),
  url: nonEmpty(2000).pipe(z.url()).refine((u) => u.startsWith('https://'), 'Webhooks must use https.'),
  event_types: z.string().nullish().transform((s) => (s ?? '').split(',').map((x) => x.trim()).filter(Boolean)).pipe(z.array(z.string().regex(/^[a-z_.]+$/, 'Event names look like certificate.issued.')).min(1, 'Enter at least one event type.')),
  secret: optionalString(512),
})
export type WebhookFormOutput = z.output<typeof webhookSchema>

export const acmeEmail = email
