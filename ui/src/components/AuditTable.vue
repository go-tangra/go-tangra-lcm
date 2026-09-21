<script setup lang="ts">
import { onMounted, watch } from 'vue'
import { useDirectory } from '@/stores/directory'
import type { AuditItem } from '@/api/types'

const props = defineProps<{ items: AuditItem[] }>()
const dir = useDirectory()

onMounted(async () => {
  await dir.loadRoles()
  await dir.resolveUsers(props.items.map((i) => i.actor_id))
})
watch(
  () => props.items,
  (items) => dir.resolveUsers(items.map((i) => i.actor_id)),
)

function actor(i: AuditItem): string {
  if (i.actor_kind === 'system') return 'system'
  if (i.actor_kind === 'service') return dir.userName(i.actor_id)
  return dir.userName(i.actor_id) || '—'
}
function subject(i: AuditItem): string {
  return i.subject_name || i.subject_id || i.subject_kind || ''
}
</script>

<template>
  <v-table density="compact" data-test="audit-table">
    <thead>
      <tr>
        <th>When</th>
        <th>Event</th>
        <th>Actor</th>
        <th>Subject</th>
        <th>Outcome</th>
      </tr>
    </thead>
    <tbody>
      <tr v-for="(i, idx) in props.items" :key="idx" data-test="audit-row">
        <td class="text-no-wrap">{{ new Date(i.ts).toLocaleString() }}</td>
        <td>{{ i.event_type }}</td>
        <td data-test="audit-actor-cell">{{ actor(i) }}</td>
        <td data-test="audit-subject-cell">{{ subject(i) }}</td>
        <td>
          <v-chip size="x-small" :color="i.outcome === 'ok' ? 'success' : i.outcome === 'refused' ? 'warning' : 'error'" variant="tonal">{{ i.outcome }}</v-chip>
        </td>
      </tr>
      <tr v-if="!props.items.length">
        <td colspan="5" class="text-medium-emphasis">No audit events.</td>
      </tr>
    </tbody>
  </v-table>
</template>
