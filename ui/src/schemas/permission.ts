import { z } from 'zod'
import { isoDate } from '@go-tangra/ui/forms'

export const RELATIONS = ['viewer', 'sharer', 'editor', 'owner'] as const

/** The server refuses an audit range wider than this (to defaults to now). */
export const MAX_AUDIT_SPAN_DAYS = 90
export const AUDIT_SPAN_MESSAGE = `Date range is limited to ${MAX_AUDIT_SPAN_DAYS} days.`
const MAX_AUDIT_SPAN_MS = MAX_AUDIT_SPAN_DAYS * 24 * 60 * 60 * 1000

export const auditFilterSchema = z
  .object({
    event_type: z.string().trim().max(100).optional(),
    actor_id: z.string().trim().max(200).optional(),
    from: isoDate,
    to: isoDate,
  })
  .refine((f) => !f.from || !f.to || f.to >= f.from, { message: 'Must not be before the start date.', path: ['to'] })
  .refine((f) => !f.from || (f.to ? Date.parse(f.to) : Date.now()) - Date.parse(f.from) <= MAX_AUDIT_SPAN_MS, {
    message: AUDIT_SPAN_MESSAGE,
    path: ['from'],
  })
