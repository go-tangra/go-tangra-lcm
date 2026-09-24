import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api } from '@/api/client'
import type { DnsProvider, Issuer, IssuerInput, Page } from '@/api/types'

export const useIssuers = defineStore('lcm-issuers', () => {
  const items = ref<Issuer[]>([])
  const next = ref<string | undefined>()
  const dnsProviders = ref<DnsProvider[]>([])
  const loading = ref(false)
  const error = ref('')

  async function list(cursor?: string): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      const page = await api<Page<Issuer>>('GET', 'issuers', undefined, { query: { cursor, limit: 50 } })
      items.value = cursor ? [...items.value, ...page.items] : page.items
      next.value = page.next_cursor
    } catch (e) {
      error.value = (e as Error).message
    } finally {
      loading.value = false
    }
  }

  async function get(id: string): Promise<Issuer> {
    return api<Issuer>('GET', 'issuers/' + id)
  }

  async function loadDnsProviders(): Promise<void> {
    if (dnsProviders.value.length) return
    try {
      const res = await api<{ items: DnsProvider[] }>('GET', 'dns-providers')
      dnsProviders.value = res.items ?? []
    } catch {
      /* leave empty; the editor shows a free-form fallback */
    }
  }

  async function create(input: IssuerInput): Promise<Issuer> {
    const i = await api<Issuer>('POST', 'issuers', input)
    items.value = [i, ...items.value]
    return i
  }

  async function update(id: string, input: IssuerInput): Promise<Issuer> {
    const i = await api<Issuer>('PUT', 'issuers/' + id, input)
    items.value = items.value.map((x) => (x.id === id ? i : x))
    if (i.is_default) items.value = items.value.map((x) => (x.id !== id && x.trust_domain === i.trust_domain ? { ...x, is_default: false } : x))
    return i
  }

  async function remove(id: string): Promise<void> {
    await api('POST', 'issuers/' + id + '/remove')
    items.value = items.value.filter((x) => x.id !== id)
  }

  return { items, next, dnsProviders, loading, error, list, get, loadDnsProviders, create, update, remove }
})
