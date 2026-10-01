import { ref } from 'vue'
import type { ListQueryOptions } from '@go-tangra/ui'
import { api, describe } from '@/api/client'
import type { ListParams, Page } from '@/api/types'

// Server-paged lists (go-tangra specs/032-server-side-tables): every table
// asks the server for one page (page, page_size, sort, order) and shows the
// total, which counts only the records the caller may read; sorting orders
// the whole list on the server.

export const PAGE_SIZE = 25
/** The largest page the server answers: option lists (selects). */
export const OPTIONS_SIZE = 200

/** The kit list-query options and the first page of a list with these sort fields. */
export function listSpec(sortable: readonly string[], key: string, dir: 'asc' | 'desc' = 'asc', size = PAGE_SIZE): { opts: ListQueryOptions; first: ListParams } {
  return {
    opts: { sortable: [...sortable], defaultSort: { key, dir }, defaultSize: size },
    first: { page: 1, page_size: size, sort: key, order: dir },
  }
}

// The sort fields each lcm list accepts (api/openapi/lcm.yaml, store/lists.go).
export const CERTIFICATE_LIST = listSpec(['identity', 'issuer', 'kind', 'status', 'not_before', 'not_after', 'created_at'], 'created_at', 'desc')
export const ISSUER_LIST = listSpec(['name', 'type', 'trust_domain', 'created_at'], 'name')
export const REQUEST_LIST = listSpec(['identity', 'kind', 'status', 'created_at'], 'created_at', 'desc')
export const JOB_LIST = listSpec(['type', 'status', 'attempts', 'run_after', 'created_at'], 'created_at', 'desc')
export const SECRET_LIST = listSpec(['name', 'kind', 'created_at'], 'name')
export const WEBHOOK_LIST = listSpec(['name', 'created_at'], 'name')
export const AUDIT_LIST = listSpec(['ts'], 'ts', 'desc', 50)

/** Blank filter values are not sent. */
function compact(f: object): Record<string, string | number> {
  const out: Record<string, string | number> = {}
  for (const [k, v] of Object.entries(f)) if (v !== undefined && v !== null && v !== '') out[k] = v as string | number
  return out
}

/**
 * The state of one server-paged list at path. list() loads one page with the
 * filter and resolves with it, or null when it failed or a newer request
 * superseded it (its rows are then ignored); reload() reloads the current
 * page (a no-op until the list was first loaded). explain, when given, may
 * word a failure more specifically than the generic reason text.
 */
export function pagedList<T, F extends object = Record<string, never>>(path: string, first: ListParams, explain?: (e: unknown) => string | undefined) {
  const items = ref<T[]>([])
  const total = ref(0)
  const params = ref<ListParams>({ ...first })
  const filter = ref<F>({} as F)
  const loading = ref(false)
  const loaded = ref(false)
  const error = ref('')
  let seq = 0

  async function list(f: F = filter.value as F, q: ListParams = params.value): Promise<Page<T> | null> {
    const mine = ++seq
    loading.value = true
    error.value = ''
    filter.value = { ...f } as typeof filter.value
    params.value = { ...q }
    loaded.value = true
    try {
      const res = await api<Page<T>>('GET', path, undefined, { query: { ...compact(f), ...q } })
      if (mine !== seq) return null
      items.value = (res.items ?? []) as typeof items.value
      total.value = res.total ?? 0
      return res
    } catch (e) {
      if (mine === seq) error.value = explain?.(e) ?? describe(e)
      return null
    } finally {
      if (mine === seq) loading.value = false
    }
  }
  const reload = (): Promise<Page<T> | null> => (loaded.value ? list() : Promise.resolve(null))

  return { items, total, params, filter, loading, loaded, error, list, reload }
}

/** Loads up to OPTIONS_SIZE records of a list for a select, in the given order. */
export async function loadOptions<T>(path: string, sort: string, filter: object = {}): Promise<T[]> {
  const res = await api<Page<T>>('GET', path, undefined, { query: { ...compact(filter), page: 1, page_size: OPTIONS_SIZE, sort, order: 'asc' } })
  return res.items ?? []
}
