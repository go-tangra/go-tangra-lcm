import { z } from 'zod'
import { isoDate } from '@go-tangra/ui/forms'

export const RELATIONS = ['viewer', 'sharer', 'editor', 'owner'] as const

export const auditFilterSchema = z.object({
  event_type: z.string().trim().max(100).optional(),
  actor_id: z.string().trim().max(200).optional(),
  from: isoDate,
  to: isoDate,
})
