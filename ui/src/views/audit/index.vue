<script setup lang="ts">
import { onMounted, reactive } from 'vue'
import { useOps } from '@/stores/ops'
import AuditTable from '@/components/AuditTable.vue'

const ops = useOps()
const filter = reactive({ event_type: '', actor_id: '', from: '', to: '' })

function apply(): void {
  void ops.loadAudit({
    event_type: filter.event_type || undefined,
    actor_id: filter.actor_id || undefined,
    from: filter.from || undefined,
    to: filter.to || undefined,
  })
}

onMounted(() => apply())
</script>

<template>
  <div>
    <h1 class="text-h5 mb-4">Audit</h1>
    <v-row class="mb-2" dense>
      <v-col cols="12" md="3"><v-text-field v-model="filter.event_type" label="Event type" density="compact" clearable data-test="audit-filter-event" @keyup.enter="apply" @click:clear="apply" /></v-col>
      <v-col cols="12" md="3"><v-text-field v-model="filter.actor_id" label="Actor id" density="compact" clearable data-test="audit-filter-actor" @keyup.enter="apply" @click:clear="apply" /></v-col>
      <v-col cols="12" md="2"><v-text-field v-model="filter.from" label="From (ISO)" density="compact" clearable data-test="audit-filter-from" @keyup.enter="apply" /></v-col>
      <v-col cols="12" md="2"><v-text-field v-model="filter.to" label="To (ISO)" density="compact" clearable data-test="audit-filter-to" @keyup.enter="apply" /></v-col>
      <v-col cols="12" md="2" class="d-flex align-center"><v-btn color="primary" size="small" data-test="audit-apply" @click="apply">Apply</v-btn></v-col>
    </v-row>
    <v-alert v-if="ops.error" type="error" variant="tonal" density="compact" class="mb-3">{{ ops.error }}</v-alert>
    <AuditTable :items="ops.audit" />
    <div v-if="ops.auditNext" class="mt-3 text-center">
      <v-btn variant="text" data-test="audit-more" @click="ops.loadAudit({ event_type: filter.event_type || undefined, actor_id: filter.actor_id || undefined, from: filter.from || undefined, to: filter.to || undefined }, ops.auditNext)">Load more</v-btn>
    </div>
  </div>
</template>
