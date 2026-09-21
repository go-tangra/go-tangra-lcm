<script setup lang="ts">
import { computed } from 'vue'
import type { Stats } from '@/api/types'

const props = defineProps<{ stats: Stats | null }>()

const sum = (m: Record<string, number> | undefined): number => Object.values(m ?? {}).reduce((a, b) => a + b, 0)

const tiles = computed(() => {
  const s = props.stats
  if (!s) return []
  return [
    { key: 'certificates', label: 'Certificates', value: sum(s.certificates), icon: 'mdi-certificate-outline' },
    { key: 'issuers', label: 'Issuers', value: s.issuers, icon: 'mdi-shield-key-outline' },
    { key: 'jobs', label: 'Jobs', value: sum(s.jobs), icon: 'mdi-clipboard-list-outline' },
    { key: 'clients', label: 'Clients', value: s.clients, icon: 'mdi-account-network-outline' },
    { key: 'expiring', label: 'Expiring soon', value: s.expiring_soon, icon: 'mdi-clock-alert-outline' },
    { key: 'errors', label: 'Recent errors', value: s.recent_errors, icon: 'mdi-alert-circle-outline' },
    { key: 'streams', label: 'Open streams', value: s.open_streams, icon: 'mdi-broadcast' },
  ]
})
</script>

<template>
  <v-row data-test="stats-card">
    <v-col v-for="t in tiles" :key="t.key" cols="6" md="3">
      <v-card variant="tonal" :data-test="'stat-' + t.key" :color="t.key === 'errors' && t.value > 0 ? 'error' : t.key === 'expiring' && t.value > 0 ? 'warning' : undefined">
        <v-card-text class="d-flex flex-column align-center">
          <v-icon :icon="t.icon" size="28" class="mb-1" />
          <div class="text-h5" :data-test="'stat-value-' + t.key">{{ t.value }}</div>
          <div class="text-caption text-medium-emphasis">{{ t.label }}</div>
        </v-card-text>
      </v-card>
    </v-col>
  </v-row>
</template>
