import { defineStore } from 'pinia'
import { api } from '@/api/client'
import type { CertRequest, Job } from '@/api/types'
import { JOB_LIST, pagedList, REQUEST_LIST } from '@/stores/paged'

type StatusFilter = { status?: string | undefined }

/** The certificate-requests table: one server page (only requests the caller may read). */
export const useRequestList = defineStore('lcm-request-list', () => pagedList<CertRequest, StatusFilter>('requests', REQUEST_LIST.first))

/** The jobs table: one server page (only jobs the caller may read). */
export const useJobList = defineStore('lcm-job-list', () => pagedList<Job, StatusFilter>('jobs', JOB_LIST.first))

// The Requests view covers both certificate requests (approve/reject) and the
// issuance jobs they queue (cancel/retry). Actions patch the visible row; the
// view reloads the page where a row may move.
export const useRequests = defineStore('lcm-requests', () => {
  const requests = useRequestList()
  const jobs = useJobList()

  async function approve(id: string): Promise<void> {
    const r = await api<CertRequest>('POST', 'requests/' + id + '/approve')
    requests.items = requests.items.map((x) => (x.id === id ? { ...x, ...r, status: r?.status ?? 'approved' } : x))
  }

  async function reject(id: string): Promise<void> {
    const r = await api<CertRequest>('POST', 'requests/' + id + '/reject')
    requests.items = requests.items.map((x) => (x.id === id ? { ...x, ...r, status: r?.status ?? 'rejected' } : x))
  }

  async function cancelJob(id: string): Promise<void> {
    await api('POST', 'jobs/' + id + '/cancel')
    jobs.items = jobs.items.map((j) => (j.id === id ? { ...j, status: 'failed' } : j))
  }

  async function retryJob(id: string): Promise<void> {
    const j = await api<Job>('POST', 'jobs/' + id + '/retry')
    jobs.items = jobs.items.map((x) => (x.id === id ? { ...x, ...j, status: j?.status ?? 'queued' } : x))
  }

  return { approve, reject, cancelJob, retryJob }
})
