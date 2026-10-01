<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { RouterLink } from 'vue-router'
import { UiPage, UiAlert, UiCard, UiButton, UiDataTable, UiStatusChip, UiTabs, UiForm, UiSelect, useListQuery, type Column, type SelectOption, type TabItem } from '@go-tangra/ui'
import { useZodForm } from '@go-tangra/ui/forms'
import { useJobList, useRequestList, useRequests } from '@/stores/requests'
import { JOB_LIST, REQUEST_LIST } from '@/stores/paged'
import { describe } from '@/api/client'
import { requestFilterSchema, REQUEST_STATUSES } from '@/schemas'
import type { CertRequest, Job } from '@/api/types'

const store = useRequests()
const requests = useRequestList()
const jobs = useJobList()
const tab = ref('requests')
const error = ref('')

// --- server paging and sorting, one query per table (?requests.page=…, ?jobs.page=…) ---
const rq = useListQuery('requests', REQUEST_LIST.opts)
const jq = useListQuery('jobs', JOB_LIST.opts)
let status: string | undefined
async function loadRequests(): Promise<void> {
  const res = await requests.list({ status }, rq.query.value)
  if (res?.page) rq.clampTo(res.page)
}
async function loadJobs(): Promise<void> {
  const res = await jobs.list({}, jq.query.value)
  if (res?.page) jq.clampTo(res.page)
}
watch(rq.query, () => void loadRequests())
watch(jq.query, () => void loadJobs())
onMounted(async () => {
  await Promise.all([loadRequests(), loadJobs()])
})
const tabs = computed<TabItem[]>(() => [{ key: 'requests', label: 'Certificate requests', count: requests.total }, { key: 'jobs', label: 'Jobs', count: jobs.total }])
const statusOptions: SelectOption[] = REQUEST_STATUSES.map((s) => ({ title: s, value: s }))
const filter = useZodForm(requestFilterSchema, {
  onSubmit: async (f) => {
    status = f.status
    // A filter change starts at page 1 (which reloads), else reload in place.
    if (rq.page.value !== 1) rq.resetPage()
    else await loadRequests()
  },
})
async function act(fn: () => Promise<void>, reload: () => Promise<void>): Promise<void> {
  error.value = ''
  try {
    await fn()
    // The row's status changed: under a status filter or sort it may move.
    await reload()
  } catch (e) {
    error.value = describe(e)
  }
}
// An ACME order (kind generic) has domains instead of a SPIFFE ID.
const identity = (r: CertRequest) => (r.kind === 'generic' ? (r.sans ?? []).join(', ') : r.spiffe_id)
const statusColors = { pending: 'warning', processing: 'info', approved: 'info', issued: 'success', rejected: 'error', failed: 'error' } as const
const requestColumns: Column<CertRequest>[] = [
  { key: 'identity', label: 'SPIFFE ID / domains', format: identity, sortable: true },
  { key: 'kind', label: 'Kind', width: 'sm', format: (r) => (r.kind === 'generic' ? 'generic' : 'SVID'), hideOnStack: true, sortable: true },
  { key: 'status', label: 'Status', width: 'sm', sortable: true },
  { key: 'reason', label: 'Reason', format: (r) => r.reason ?? '' },
  { key: 'created_at', label: 'Requested', format: (r) => (r.created_at ? new Date(r.created_at).toLocaleString() : ''), hideOnStack: true, sortable: true },
]
const jobColumns: Column<Job>[] = [
  { key: 'type', label: 'Type', sortable: true },
  { key: 'status', label: 'Status', width: 'sm', sortable: true },
  { key: 'attempts', label: 'Attempts', align: 'end', format: (j) => String(j.attempts ?? 0), hideOnStack: true, sortable: true },
  { key: 'error', label: 'Error' },
  { key: 'created_at', label: 'Created', format: (j) => (j.created_at ? new Date(j.created_at).toLocaleString() : ''), hideOnStack: true, sortable: true },
]
</script>

<template>
  <UiPage title="Requests">
    <UiAlert v-if="error || requests.error || jobs.error" kind="error" class="mb-3" data-test="requests-error">{{ error || requests.error || jobs.error }}</UiAlert>
    <UiTabs v-model="tab" :tabs="tabs" class="mb-3" />
    <template v-if="tab === 'requests'">
      <UiForm :form="filter" class="mb-3 max-w-xs">
        <UiSelect v-bind="filter.field('status')" label="Status" :options="statusOptions" size="sm" data-test="requests-filter" @update:model-value="filter.submit()" />
      </UiForm>
      <UiCard :padded="false">
        <UiDataTable :items="requests.items" :columns="requestColumns" :loading="requests.loading" :total="requests.total" :page="rq.page.value" :page-size="rq.pageSize.value" :sort="rq.sort.value" caption="Certificate requests" empty-title="No requests" :row-attrs="(r) => ({ 'data-test': 'request-row-' + r.id })" data-test="requests-table" @update:page="rq.setPage" @update:page-size="rq.setPageSize" @update:sort="rq.setSort">
          <template #cell-status="{ row }"><UiStatusChip :status="row.status" :colors="statusColors" /></template>
          <template #actions="{ row }">
            <RouterLink v-if="row.status === 'issued' && row.certificate_id" :to="{ path: '/lcm/certificates', query: { id: row.certificate_id } }" class="btn btn-text btn-xs" :data-test="'request-cert-' + row.id">View certificate</RouterLink>
            <template v-if="row.status === 'pending'">
              <UiButton size="xs" variant="text" color="success" :data-test="'request-approve-' + row.id" @click="act(() => store.approve(row.id), loadRequests)">Approve</UiButton>
              <UiButton size="xs" variant="text" color="error" :data-test="'request-reject-' + row.id" @click="act(() => store.reject(row.id), loadRequests)">Reject</UiButton>
            </template>
          </template>
        </UiDataTable>
      </UiCard>
    </template>
    <UiCard v-else :padded="false">
      <UiDataTable :items="jobs.items" :columns="jobColumns" :loading="jobs.loading" :total="jobs.total" :page="jq.page.value" :page-size="jq.pageSize.value" :sort="jq.sort.value" caption="Jobs" empty-title="No jobs" :row-attrs="(j) => ({ 'data-test': 'job-row-' + j.id })" data-test="jobs-table" @update:page="jq.setPage" @update:page-size="jq.setPageSize" @update:sort="jq.setSort">
        <template #cell-status="{ row }"><UiStatusChip :status="row.status" :colors="{ processing: 'info', queued: 'neutral' }" /></template>
        <template #actions="{ row }">
          <UiButton v-if="row.status === 'failed'" size="xs" variant="text" :data-test="'job-retry-' + row.id" @click="act(() => store.retryJob(row.id), loadJobs)">Retry</UiButton>
          <UiButton v-if="row.status === 'queued' || row.status === 'processing'" size="xs" variant="text" color="error" :data-test="'job-cancel-' + row.id" @click="act(() => store.cancelJob(row.id), loadJobs)">Cancel</UiButton>
        </template>
      </UiDataTable>
    </UiCard>
  </UiPage>
</template>
