<script setup lang="ts">
import { onMounted } from 'vue'
import { useOps } from '@/stores/ops'
import { useCertificates } from '@/stores/certificates'
import StatsCard from '@/components/StatsCard.vue'

const ops = useOps()
const certs = useCertificates()

onMounted(async () => {
  await Promise.all([ops.loadStats(), certs.list({ status: 'expiring' })])
})

function chipColor(status: string): string {
  return status === 'active' ? 'success' : status === 'expiring' ? 'warning' : status === 'revoked' ? 'error' : 'grey'
}
</script>

<template>
  <div>
    <h1 class="text-h5 mb-4">Dashboard</h1>
    <v-alert v-if="ops.error" type="error" variant="tonal" density="compact" class="mb-3">{{ ops.error }}</v-alert>
    <StatsCard :stats="ops.stats" />
    <v-card class="mt-4" title="Certificates by status" data-test="dashboard-by-status">
      <v-card-text>
        <template v-if="ops.stats">
          <v-chip v-for="(count, status) in ops.stats.certificates" :key="status" size="small" :color="chipColor(String(status))" variant="tonal" class="mr-2 mb-2" :data-test="'by-status-' + status">
            {{ status }}: {{ count }}
          </v-chip>
        </template>
        <div v-else class="text-medium-emphasis">Loading…</div>
      </v-card-text>
    </v-card>
    <v-card class="mt-4" title="Expiring soon" data-test="dashboard-expiring">
      <v-list density="compact">
        <v-list-item
          v-for="c in certs.items"
          :key="c.id"
          :title="c.spiffe_id"
          :subtitle="c.not_after ? 'expires ' + new Date(c.not_after).toLocaleString() : ''"
          :to="'/lcm/certificates'"
          :data-test="'expiring-' + c.id"
        >
          <template #append><v-chip size="x-small" color="warning" variant="tonal">{{ c.status }}</v-chip></template>
        </v-list-item>
        <v-list-item v-if="!certs.items.length" title="Nothing expiring soon." />
      </v-list>
    </v-card>
  </div>
</template>
