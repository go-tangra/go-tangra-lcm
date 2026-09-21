<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useOps } from '@/stores/ops'
import { useCertificates } from '@/stores/certificates'
import { useLive } from '@/stores/live'

// Shown in the shell app bar. Opens the shared live stream, shows a badge for
// certificates expiring soon and previews the most recent live events. The
// shell only mounts it for a person who can reach the module (certificates:read).
const ops = useOps()
const certs = useCertificates()
const live = useLive()
const open = ref(false)
const events = ref<string[]>([])
let release: (() => void) | null = null
let off: (() => void) | null = null

const expiring = computed(() => ops.stats?.expiring_soon ?? 0)

onMounted(async () => {
  await ops.loadStats()
  off = live.on((type) => {
    if (type.startsWith('certificate.')) events.value = [type, ...events.value].slice(0, 6)
  })
  release = live.connect()
})

onUnmounted(() => {
  off?.()
  release?.()
  release = null
})

async function toggle(): Promise<void> {
  open.value = !open.value
  if (open.value) await ops.loadStats()
}
</script>

<template>
  <v-menu v-model="open" :close-on-content-click="false" location="bottom end" data-test="header-cert">
    <template #activator="{ props: menuProps }">
      <v-btn v-bind="menuProps" icon variant="text" aria-label="Certificates" data-test="cert-button" @click="toggle">
        <v-badge :model-value="expiring > 0" :content="expiring" color="warning" data-test="cert-badge">
          <v-icon icon="mdi-certificate-outline" />
        </v-badge>
      </v-btn>
    </template>
    <v-card min-width="320" max-width="420">
      <v-card-title class="d-flex align-center">
        Certificates
        <v-spacer />
        <v-btn size="small" variant="text" to="/lcm/certificates" data-test="cert-open" @click="open = false">Open</v-btn>
      </v-card-title>
      <v-card-text>
        <div class="text-caption text-medium-emphasis mb-2">
          {{ expiring }} expiring soon · {{ certs.items.length }} loaded
        </div>
        <div v-if="!events.length" class="text-caption text-medium-emphasis" data-test="cert-events-empty">No live events yet.</div>
        <v-list v-else density="compact" data-test="cert-events">
          <v-list-item v-for="(e, i) in events" :key="i" :title="e" />
        </v-list>
      </v-card-text>
    </v-card>
  </v-menu>
</template>
