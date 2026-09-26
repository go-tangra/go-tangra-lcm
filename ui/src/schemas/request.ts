import { z } from 'zod'

export const REQUEST_STATUSES = ['pending', 'processing', 'approved', 'issued', 'rejected', 'failed'] as const
export const requestFilterSchema = z.object({ status: z.enum(REQUEST_STATUSES).optional() })
