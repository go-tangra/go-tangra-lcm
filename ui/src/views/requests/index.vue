<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRequests } from '@/stores/requests'
import { describe } from '@/api/client'
import type { RequestStatus } from '@/api/types'

const store = useRequests()
const tab = ref<'requests' | 'jobs'>('requests')
const err = ref('')
const reqStatus = ref<RequestStatus | null>(null)
const requestStatuses: RequestStatus[] = ['pending', 'approved', 'rejected', 'issued']

onMounted(async () => {
  await Promise.all([store.listRequests(), store.listJobs()])
})

async function act(fn: () => Promise<void>): Promise<void> {
  err.value = ''
  try {
    await fn()
  } catch (e) {
    err.value = describe(e)
  }
}

function reqColor(s: string): string {
  return s === 'issued' ? 'success' : s === 'approved' ? 'info' : s === 'rejected' ? 'error' : 'warning'
}
function jobColor(s: string): string {
  return s === 'completed' ? 'success' : s === 'failed' ? 'error' : s === 'processing' ? 'info' : 'grey'
}
</script>

<template>
  <div>
    <h1 class="text-h5 mb-4">Requests</h1>
    <v-alert v-if="err" type="error" variant="tonal" density="compact" class="mb-3" data-test="requests-error">{{ err }}</v-alert>
    <v-tabs v-model="tab" class="mb-3">
      <v-tab value="requests" data-test="tab-requests">Certificate requests</v-tab>
      <v-tab value="jobs" data-test="tab-jobs">Jobs</v-tab>
    </v-tabs>
    <v-window v-model="tab">
      <v-window-item value="requests">
        <v-select v-model="reqStatus" :items="requestStatuses" label="Status" density="compact" clearable style="max-width: 240px" class="mb-2" data-test="requests-filter" @update:model-value="store.listRequests(reqStatus ?? undefined)" />
        <v-table data-test="requests-table">
          <thead>
            <tr><th>SPIFFE ID</th><th>Status</th><th>Requested</th><th class="text-right">Actions</th></tr>
          </thead>
          <tbody>
            <tr v-for="r in store.requests" :key="r.id" :data-test="'request-row-' + r.id">
              <td class="text-truncate" style="max-width: 320px">{{ r.spiffe_id }}</td>
              <td><v-chip size="x-small" :color="reqColor(r.status)" variant="tonal">{{ r.status }}</v-chip></td>
              <td class="text-no-wrap">{{ r.created_at ? new Date(r.created_at).toLocaleString() : '—' }}</td>
              <td class="text-right">
                <template v-if="r.status === 'pending'">
                  <v-btn size="x-small" color="success" variant="text" :data-test="'request-approve-' + r.id" @click="act(() => store.approve(r.id))">Approve</v-btn>
                  <v-btn size="x-small" color="error" variant="text" :data-test="'request-reject-' + r.id" @click="act(() => store.reject(r.id))">Reject</v-btn>
                </template>
              </td>
            </tr>
            <tr v-if="!store.requests.length"><td colspan="4" class="text-medium-emphasis">No requests.</td></tr>
          </tbody>
        </v-table>
      </v-window-item>
      <v-window-item value="jobs">
        <v-table data-test="jobs-table">
          <thead>
            <tr><th>Type</th><th>Status</th><th>Attempts</th><th>Error</th><th class="text-right">Actions</th></tr>
          </thead>
          <tbody>
            <tr v-for="j in store.jobs" :key="j.id" :data-test="'job-row-' + j.id">
              <td>{{ j.type ?? '—' }}</td>
              <td><v-chip size="x-small" :color="jobColor(j.status)" variant="tonal">{{ j.status }}</v-chip></td>
              <td>{{ j.attempts ?? 0 }}</td>
              <td class="text-truncate" style="max-width: 220px">{{ j.error ?? '' }}</td>
              <td class="text-right">
                <v-btn v-if="j.status === 'failed'" size="x-small" color="primary" variant="text" :data-test="'job-retry-' + j.id" @click="act(() => store.retryJob(j.id))">Retry</v-btn>
                <v-btn v-if="j.status === 'queued' || j.status === 'processing'" size="x-small" color="error" variant="text" :data-test="'job-cancel-' + j.id" @click="act(() => store.cancelJob(j.id))">Cancel</v-btn>
              </td>
            </tr>
            <tr v-if="!store.jobs.length"><td colspan="5" class="text-medium-emphasis">No jobs.</td></tr>
          </tbody>
        </v-table>
      </v-window-item>
    </v-window>
  </div>
</template>
