<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { UiPage, UiAlert, UiCard, UiForm, UiInput, UiButton, UiDataTable, UiStatusChip, useListQuery, type Column } from '@go-tangra/ui'
import { useZodForm } from '@go-tangra/ui/forms'
import { useAuditList } from '@/stores/ops'
import { AUDIT_LIST } from '@/stores/paged'
import { useDirectory } from '@/stores/directory'
import { auditFilterSchema } from '@/schemas'
import type { AuditFilter, AuditItem } from '@/api/types'

// Module-specific audit view: actors resolve through the auth directory
// (users, roles and mesh services) rather than showing raw ids. The server
// pages the events newest first; without from/to it covers the last 7 days.
const audit = useAuditList()
const dir = useDirectory()

// --- server paging and sorting (page / size / order in the URL: ?audit.page=…) ---
const lq = useListQuery('audit', AUDIT_LIST.opts)
const current = ref<AuditFilter>({})
async function load(): Promise<void> {
  const res = await audit.list(current.value, lq.query.value)
  if (res?.page) lq.clampTo(res.page)
}
watch(lq.query, () => void load())
const filter = useZodForm(auditFilterSchema, {
  initial: { event_type: '', actor_id: '', from: '', to: '' },
  onSubmit: async (f) => {
    current.value = { event_type: f.event_type || undefined, actor_id: f.actor_id || undefined, from: f.from, to: f.to }
    if (lq.page.value !== 1) lq.resetPage()
    else await load()
  },
})
const apply = () => void filter.submit()
onMounted(async () => {
  await dir.loadRoles()
  await load()
})
watch(() => audit.items, (items) => dir.resolveUsers(items.map((i) => i.actor_id)))
const actor = (i: AuditItem) => (i.actor_kind === 'system' ? 'system' : dir.userName(i.actor_id) || '')
const columns: Column<AuditItem>[] = [
  { key: 'ts', label: 'When', format: (i) => new Date(i.ts).toLocaleString(), sortable: true },
  { key: 'event_type', label: 'Event' },
  { key: 'actor', label: 'Actor', format: actor },
  { key: 'subject', label: 'Subject', format: (i) => i.subject_name || i.subject_id || i.subject_kind || '', hideOnStack: true },
  { key: 'outcome', label: 'Outcome', width: 'sm' },
]
const windowHint = computed(() => (current.value.from || current.value.to ? '' : 'Showing the last 7 days. Set From / To for older events.'))
</script>

<template>
  <UiPage title="Audit">
    <template #filters>
      <UiForm :form="filter" class="w-full">
        <div class="grid grid-cols-2 gap-2 md:grid-cols-12 md:items-end">
          <div class="md:col-span-3"><UiInput v-bind="filter.field('event_type')" label="Event type" size="sm" data-test="audit-filter-event" @enter="apply" /></div>
          <div class="md:col-span-3"><UiInput v-bind="filter.field('actor_id')" label="Actor id" size="sm" data-test="audit-filter-actor" @enter="apply" /></div>
          <div class="md:col-span-2"><UiInput v-bind="filter.field('from')" label="From" type="date" size="sm" data-test="audit-filter-from" /></div>
          <div class="md:col-span-2"><UiInput v-bind="filter.field('to')" label="To" type="date" size="sm" data-test="audit-filter-to" /></div>
          <div class="col-span-2 md:col-span-2"><UiButton block size="sm" data-test="audit-apply" @click="apply">Apply</UiButton></div>
        </div>
      </UiForm>
    </template>
    <UiAlert v-if="audit.error" kind="error" class="mb-3">{{ audit.error }}</UiAlert>
    <p v-if="windowHint" class="mb-2 text-sm text-base-content/70" data-test="audit-window">{{ windowHint }}</p>
    <UiCard :padded="false">
      <UiDataTable :items="audit.items" :columns="columns" :loading="audit.loading" :total="audit.total" :page="lq.page.value" :page-size="lq.pageSize.value" :sort="lq.sort.value" caption="Audit events" empty-title="No events" data-test="audit-table" @update:page="lq.setPage" @update:page-size="lq.setPageSize" @update:sort="lq.setSort">
        <template #cell-outcome="{ row }"><UiStatusChip :status="row.outcome" :colors="{ ok: 'success', success: 'success', refused: 'warning', denied: 'error', failure: 'error' }" /></template>
      </UiDataTable>
    </UiCard>
  </UiPage>
</template>
