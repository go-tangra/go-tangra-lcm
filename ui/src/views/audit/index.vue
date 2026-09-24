<script setup lang="ts">
import { computed, onMounted, watch } from 'vue'
import { UiPage, UiAlert, UiCard, UiForm, UiInput, UiButton, UiDataTable, UiStatusChip, type Column } from '@go-tangra/ui'
import { useZodForm } from '@go-tangra/ui/forms'
import { useOps } from '@/stores/ops'
import { useDirectory } from '@/stores/directory'
import { auditFilterSchema } from '@/schemas'
import type { AuditItem } from '@/api/types'

// Module-specific audit view: actors resolve through the auth directory
// (users, roles and mesh services) rather than showing raw ids.
const ops = useOps()
const dir = useDirectory()
const filter = useZodForm(auditFilterSchema, {
  initial: { event_type: '', actor_id: '', from: '', to: '' },
  onSubmit: (f) => ops.loadAudit({ event_type: f.event_type || undefined, actor_id: f.actor_id || undefined, from: f.from, to: f.to }),
})
const apply = () => void filter.submit()
const more = () => {
  const f = filter.validate()
  if (f) void ops.loadAudit({ event_type: f.event_type || undefined, actor_id: f.actor_id || undefined, from: f.from, to: f.to }, ops.auditNext)
}
onMounted(async () => {
  await dir.loadRoles()
  apply()
})
watch(() => ops.audit, (items) => dir.resolveUsers(items.map((i) => i.actor_id)))
const actor = (i: AuditItem) => (i.actor_kind === 'system' ? 'system' : dir.userName(i.actor_id) || '')
const rows = computed(() => ops.audit.map((i, n) => ({ ...i, id: i.ts + ':' + n })))
const columns: Column<(typeof rows.value)[number]>[] = [
  { key: 'ts', label: 'When', format: (i) => new Date(i.ts).toLocaleString() },
  { key: 'event_type', label: 'Event' },
  { key: 'actor', label: 'Actor', format: actor },
  { key: 'subject', label: 'Subject', format: (i) => i.subject_name || i.subject_id || i.subject_kind || '', hideOnStack: true },
  { key: 'outcome', label: 'Outcome', width: 'sm' },
]
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
    <UiAlert v-if="ops.error" kind="error" class="mb-3">{{ ops.error }}</UiAlert>
    <UiCard :padded="false">
      <UiDataTable :items="rows" :columns="columns" :loading="ops.loading" caption="Audit events" empty-title="No events" :has-more="!!ops.auditNext" data-test="audit-table" @load-more="more">
        <template #cell-outcome="{ row }"><UiStatusChip :status="row.outcome" :colors="{ ok: 'success', success: 'success', refused: 'warning', denied: 'error', failure: 'error' }" /></template>
      </UiDataTable>
    </UiCard>
  </UiPage>
</template>
