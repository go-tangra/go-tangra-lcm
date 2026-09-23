<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { RouterLink } from 'vue-router'
import { UiIcon, UiBadge } from '@freya/ui'
import { useOps } from '@/stores/ops'
import { useCertificates } from '@/stores/certificates'
import { useLive } from '@/stores/live'

// Shown in the shell app bar (./header). Opens the shared live stream, shows a
// badge for certificates expiring soon and previews the most recent live
// events. The shell only mounts it for a person who can reach the module.
// Module-unique: a small popover on kit primitives, no shared component wraps it.
const ops = useOps()
const certs = useCertificates()
const live = useLive()
const open = ref(false)
const events = ref<string[]>([])
const root = ref<HTMLElement | null>(null)
let release: (() => void) | null = null
let off: (() => void) | null = null

const expiring = computed(() => ops.stats?.expiring_soon ?? 0)

function onDoc(e: MouseEvent): void {
  if (open.value && root.value && !root.value.contains(e.target as Node)) open.value = false
}
function onKey(e: KeyboardEvent): void {
  if (e.key === 'Escape') open.value = false
}
onMounted(async () => {
  document.addEventListener('mousedown', onDoc)
  document.addEventListener('keydown', onKey)
  await ops.loadStats()
  off = live.on((type) => {
    if (type.startsWith('certificate.')) events.value = [type, ...events.value].slice(0, 6)
  })
  release = live.connect()
})
onUnmounted(() => {
  document.removeEventListener('mousedown', onDoc)
  document.removeEventListener('keydown', onKey)
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
  <div ref="root" class="relative" data-test="header-cert">
    <button type="button" class="btn btn-text btn-circle btn-sm relative" aria-label="Certificates" :aria-expanded="open" aria-haspopup="dialog" data-test="cert-button" @click="toggle">
      <UiIcon name="mdi-certificate-outline" />
      <span v-if="expiring > 0" class="badge badge-warning badge-xs absolute -top-1 -end-1" data-test="cert-badge">{{ expiring }}</span>
    </button>
    <div v-if="open" role="dialog" aria-label="Certificates" class="absolute end-0 z-50 mt-1 w-80 rounded-box border border-base-300 bg-base-100 p-3 shadow-lg">
      <div class="mb-2 flex items-center gap-2">
        <span class="font-medium">Certificates</span>
        <span class="grow" />
        <RouterLink to="/lcm/certificates" class="btn btn-text btn-xs" data-test="cert-open" @click="open = false">Open</RouterLink>
      </div>
      <p class="mb-2 text-xs text-base-content/70">{{ expiring }} expiring soon · {{ certs.items.length }} loaded</p>
      <p v-if="!events.length" class="text-xs text-base-content/70" data-test="cert-events-empty">No live events yet.</p>
      <ul v-else class="flex flex-col gap-1" data-test="cert-events"><li v-for="(e, i) in events" :key="i"><UiBadge size="xs">{{ e }}</UiBadge></li></ul>
    </div>
  </div>
</template>
