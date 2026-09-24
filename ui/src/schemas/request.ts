import { z } from 'zod'

export const REQUEST_STATUSES = ['pending', 'approved', 'rejected', 'issued'] as const
export const requestFilterSchema = z.object({ status: z.enum(REQUEST_STATUSES).optional() })
