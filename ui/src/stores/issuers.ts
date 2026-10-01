import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api } from '@/api/client'
import type { DnsProvider, Issuer, IssuerInput } from '@/api/types'
import { ISSUER_LIST, loadOptions, pagedList } from '@/stores/paged'

// The issuers table is one server page (list contract; the total counts only
// the issuers the caller may read). options holds the readable issuers (up to
// the largest page) for the issuer selects of other views.
export const useIssuers = defineStore('lcm-issuers', () => {
  const { items, total, params, loading, loaded, error, list, reload } = pagedList<Issuer>('issuers', ISSUER_LIST.first)
  const options = ref<Issuer[]>([])
  const dnsProviders = ref<DnsProvider[]>([])

  async function loadOptions_(): Promise<void> {
    try {
      options.value = await loadOptions<Issuer>('issuers', 'name')
    } catch {
      options.value = []
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
    return api<Issuer>('POST', 'issuers', input)
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

  return { items, total, params, loading, loaded, error, list, reload, options, loadOptions: loadOptions_, dnsProviders, get, loadDnsProviders, create, update, remove }
})
