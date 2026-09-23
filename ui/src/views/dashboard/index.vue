<script setup lang="ts">
import { computed, onMounted } from 'vue'
import { RouterLink } from 'vue-router'
import { UiPage, UiAlert, UiCard, UiStatGrid, UiStatTile, UiBarList, UiStatusChip, UiEmptyState, type BarItem } from '@freya/ui'
import { useOps } from '@/stores/ops'
import { useCertificates } from '@/stores/certificates'

const ops = useOps()
const certs = useCertificates()
onMounted(async () => {
  await Promise.all([ops.loadStats(), certs.list({ status: 'expiring' })])
})
const sum = (m: Record<string, number> | undefined): number => Object.values(m ?? {}).reduce((a, b) => a + b, 0)
const s = computed(() => ops.stats)
const statusColor: Record<string, NonNullable<BarItem['color']>> = { active: 'success', expiring: 'warning', revoked: 'error', expired: 'neutral' }
const byStatus = computed<BarItem[]>(() => Object.entries(s.value?.certificates ?? {}).map(([label, value]) => ({ label, value, color: statusColor[label] ?? 'primary' })))
</script>

<template>
  <UiPage title="Dashboard">
    <UiAlert v-if="ops.error" kind="error" class="mb-3">{{ ops.error }}</UiAlert>
    <UiStatGrid v-if="s" class="mb-4" :cols="4" data-test="stats-card">
      <UiStatTile title="Certificates" :value="sum(s.certificates)" icon="mdi-certificate-outline" color="primary" data-test="stat-certificates" />
      <UiStatTile title="Issuers" :value="s.issuers" icon="mdi-shield-key-outline" color="info" data-test="stat-issuers" />
      <UiStatTile title="Jobs" :value="sum(s.jobs)" icon="mdi-clipboard-list-outline" data-test="stat-jobs" />
      <UiStatTile title="Clients" :value="s.clients" icon="mdi-account-network-outline" data-test="stat-clients" />
      <UiStatTile title="Expiring soon" :value="s.expiring_soon" icon="mdi-clock-alert-outline" :color="s.expiring_soon > 0 ? 'warning' : 'neutral'" data-test="stat-expiring" />
      <UiStatTile title="Recent errors" :value="s.recent_errors" icon="mdi-alert-circle-outline" :color="s.recent_errors > 0 ? 'error' : 'neutral'" data-test="stat-errors" />
      <UiStatTile title="Open streams" :value="s.open_streams" icon="mdi-broadcast" data-test="stat-streams" />
    </UiStatGrid>
    <div class="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <UiCard title="Certificates by status" data-test="dashboard-by-status"><UiBarList :items="byStatus" empty-title="Loading…" /></UiCard>
      <UiCard title="Expiring soon" :padded="false" data-test="dashboard-expiring">
        <UiEmptyState v-if="!certs.items.length" title="Nothing expiring soon" icon="mdi-check-circle-outline" />
        <ul v-else class="divide-y divide-base-300">
          <li v-for="c in certs.items" :key="c.id">
            <RouterLink to="/lcm/certificates" class="flex items-center gap-3 px-4 py-2 hover:bg-base-200" :data-test="'expiring-' + c.id">
              <span class="min-w-0 grow"><span class="block truncate">{{ c.spiffe_id }}</span><span class="block text-xs text-base-content/70">{{ c.not_after ? 'expires ' + new Date(c.not_after).toLocaleString() : '' }}</span></span>
              <UiStatusChip :status="c.status" :colors="{ expiring: 'warning' }" />
            </RouterLink>
          </li>
        </ul>
      </UiCard>
    </div>
  </UiPage>
</template>
