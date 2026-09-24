import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api } from '@/api/client'
import type { CertRequest, Job, Page } from '@/api/types'

// The Requests view covers both certificate requests (approve/reject) and the
// issuance jobs they queue (cancel/retry).
export const useRequests = defineStore('lcm-requests', () => {
  const requests = ref<CertRequest[]>([])
  const requestsNext = ref<string | undefined>()
  const jobs = ref<Job[]>([])
  const jobsNext = ref<string | undefined>()
  const loading = ref(false)
  const error = ref('')

  async function listRequests(status?: string, cursor?: string): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      const page = await api<Page<CertRequest>>('GET', 'requests', undefined, { query: { status, cursor, limit: 50 } })
      requests.value = cursor ? [...requests.value, ...page.items] : page.items
      requestsNext.value = page.next_cursor
    } catch (e) {
      error.value = (e as Error).message
    } finally {
      loading.value = false
    }
  }

  async function listJobs(status?: string, cursor?: string): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      const page = await api<Page<Job>>('GET', 'jobs', undefined, { query: { status, cursor, limit: 50 } })
      jobs.value = cursor ? [...jobs.value, ...page.items] : page.items
      jobsNext.value = page.next_cursor
    } catch (e) {
      error.value = (e as Error).message
    } finally {
      loading.value = false
    }
  }

  async function approve(id: string): Promise<void> {
    const r = await api<CertRequest>('POST', 'requests/' + id + '/approve')
    requests.value = requests.value.map((x) => (x.id === id ? { ...x, ...r, status: r?.status ?? 'approved' } : x))
  }

  async function reject(id: string): Promise<void> {
    const r = await api<CertRequest>('POST', 'requests/' + id + '/reject')
    requests.value = requests.value.map((x) => (x.id === id ? { ...x, ...r, status: r?.status ?? 'rejected' } : x))
  }

  async function cancelJob(id: string): Promise<void> {
    await api('POST', 'jobs/' + id + '/cancel')
    jobs.value = jobs.value.map((j) => (j.id === id ? { ...j, status: 'failed' } : j))
  }

  async function retryJob(id: string): Promise<void> {
    const j = await api<Job>('POST', 'jobs/' + id + '/retry')
    jobs.value = jobs.value.map((x) => (x.id === id ? { ...x, ...j, status: j?.status ?? 'queued' } : x))
  }

  return { requests, requestsNext, jobs, jobsNext, loading, error, listRequests, listJobs, approve, reject, cancelJob, retryJob }
})
