<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { UiPage, UiAlert, UiCard, UiButton, UiDataTable, UiStatusChip, UiTabs, UiForm, UiSelect, type Column, type SelectOption, type TabItem } from '@freya/ui'
import { useZodForm } from '@freya/ui/forms'
import { useRequests } from '@/stores/requests'
import { describe } from '@/api/client'
import { requestFilterSchema, REQUEST_STATUSES } from '@/schemas'
import type { CertRequest, Job } from '@/api/types'

const store = useRequests()
const tab = ref('requests')
const error = ref('')
onMounted(async () => {
  await Promise.all([store.listRequests(), store.listJobs()])
})
const tabs = computed<TabItem[]>(() => [{ key: 'requests', label: 'Certificate requests', count: store.requests.length }, { key: 'jobs', label: 'Jobs', count: store.jobs.length }])
const statusOptions: SelectOption[] = REQUEST_STATUSES.map((s) => ({ title: s, value: s }))
const filter = useZodForm(requestFilterSchema, { onSubmit: (f) => store.listRequests(f.status) })
async function act(fn: () => Promise<void>): Promise<void> {
  error.value = ''
  try {
    await fn()
  } catch (e) {
    error.value = describe(e)
  }
}
const requestColumns: Column<CertRequest>[] = [
  { key: 'spiffe_id', label: 'SPIFFE ID' },
  { key: 'status', label: 'Status', width: 'sm' },
  { key: 'created_at', label: 'Requested', format: (r) => (r.created_at ? new Date(r.created_at).toLocaleString() : ''), hideOnStack: true },
]
const jobColumns: Column<Job>[] = [
  { key: 'type', label: 'Type' },
  { key: 'status', label: 'Status', width: 'sm' },
  { key: 'attempts', label: 'Attempts', align: 'end', format: (j) => String(j.attempts ?? 0), hideOnStack: true },
  { key: 'error', label: 'Error' },
]
</script>

<template>
  <UiPage title="Requests">
    <UiAlert v-if="error" kind="error" class="mb-3" data-test="requests-error">{{ error }}</UiAlert>
    <UiTabs v-model="tab" :tabs="tabs" class="mb-3" />
    <template v-if="tab === 'requests'">
      <UiForm :form="filter" class="mb-3 max-w-xs">
        <UiSelect v-bind="filter.field('status')" label="Status" :options="statusOptions" size="sm" data-test="requests-filter" @update:model-value="filter.submit()" />
      </UiForm>
      <UiCard :padded="false">
        <UiDataTable :items="store.requests" :columns="requestColumns" caption="Certificate requests" empty-title="No requests" :row-attrs="(r) => ({ 'data-test': 'request-row-' + r.id })" data-test="requests-table">
          <template #cell-status="{ row }"><UiStatusChip :status="row.status" :colors="{ approved: 'info', rejected: 'error', pending: 'warning' }" /></template>
          <template #actions="{ row }">
            <template v-if="row.status === 'pending'">
              <UiButton size="xs" variant="text" color="success" :data-test="'request-approve-' + row.id" @click="act(() => store.approve(row.id))">Approve</UiButton>
              <UiButton size="xs" variant="text" color="error" :data-test="'request-reject-' + row.id" @click="act(() => store.reject(row.id))">Reject</UiButton>
            </template>
          </template>
        </UiDataTable>
      </UiCard>
    </template>
    <UiCard v-else :padded="false">
      <UiDataTable :items="store.jobs" :columns="jobColumns" caption="Jobs" empty-title="No jobs" :row-attrs="(j) => ({ 'data-test': 'job-row-' + j.id })" data-test="jobs-table">
        <template #cell-status="{ row }"><UiStatusChip :status="row.status" :colors="{ processing: 'info', queued: 'neutral' }" /></template>
        <template #actions="{ row }">
          <UiButton v-if="row.status === 'failed'" size="xs" variant="text" :data-test="'job-retry-' + row.id" @click="act(() => store.retryJob(row.id))">Retry</UiButton>
          <UiButton v-if="row.status === 'queued' || row.status === 'processing'" size="xs" variant="text" color="error" :data-test="'job-cancel-' + row.id" @click="act(() => store.cancelJob(row.id))">Cancel</UiButton>
        </template>
      </UiDataTable>
    </UiCard>
  </UiPage>
</template>
