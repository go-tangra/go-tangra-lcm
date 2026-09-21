<script setup lang="ts">
import { onMounted, onUnmounted, reactive, ref } from 'vue'
import { useCertificates } from '@/stores/certificates'
import { useIssuers } from '@/stores/issuers'
import { useLive } from '@/stores/live'
import CertificateDrawer from '@/components/CertificateDrawer.vue'
import IssueDialog from '@/components/IssueDialog.vue'
import type { Certificate, CertificateStatus } from '@/api/types'

const store = useCertificates()
const issuers = useIssuers()
const live = useLive()
const drawer = ref(false)
const issue = ref(false)
const selected = ref<Certificate | null>(null)
const filter = reactive<{ status: CertificateStatus | null; issuer_id: string | null; spiffe_id: string }>({ status: null, issuer_id: null, spiffe_id: '' })
const statuses: CertificateStatus[] = ['active', 'expiring', 'expired', 'revoked']
let release: (() => void) | null = null
let offLive: (() => void) | null = null
const snack = reactive<{ show: boolean; text: string; color: string }>({ show: false, text: '', color: 'success' })

function reload(): void {
  void store.list({ status: filter.status ?? undefined, issuer_id: filter.issuer_id ?? undefined, spiffe_id: filter.spiffe_id || undefined })
}

onMounted(() => {
  reload()
  void issuers.list()
  // The shared SSE stream keeps the list live for issued/renewed/revoked.
  release = live.connect()
  // Async ACME issuance reports its outcome here: a fresh cert (issued) or a
  // failure toast (failed).
  offLive = live.on((type, data) => {
    if (type === 'certificate.issued') {
      const d = (data ?? {}) as { subject?: string; spiffe_id?: string }
      snack.color = 'success'
      snack.text = 'Certificate issued' + (d.subject ? ': ' + d.subject : '')
      snack.show = true
    } else if (type === 'certificate.failed') {
      const d = (data ?? {}) as { domains?: string[]; error?: string }
      snack.color = 'error'
      snack.text = 'Certificate issuance failed' + (d.domains?.length ? ' for ' + d.domains.join(', ') : '') + (d.error ? ': ' + d.error : '')
      snack.show = true
    }
  })
})
onUnmounted(() => {
  release?.()
  release = null
  offLive?.()
  offLive = null
})

function open(c: Certificate): void {
  selected.value = c
  drawer.value = true
}

function chipColor(status: string): string {
  return status === 'active' ? 'success' : status === 'expiring' ? 'warning' : status === 'revoked' ? 'error' : 'grey'
}
</script>

<template>
  <div>
    <div class="d-flex align-center mb-4">
      <h1 class="text-h5">Certificates</h1>
      <v-spacer />
      <v-btn color="primary" prepend-icon="mdi-plus" data-test="cert-issue-open" @click="issue = true">Request</v-btn>
    </div>
    <v-row class="mb-2" dense>
      <v-col cols="12" md="3"><v-select v-model="filter.status" :items="statuses" label="Status" density="compact" clearable data-test="cert-filter-status" @update:model-value="reload" /></v-col>
      <v-col cols="12" md="4"><v-select v-model="filter.issuer_id" :items="issuers.items.map((i) => ({ title: i.name, value: i.id }))" label="Issuer" density="compact" clearable data-test="cert-filter-issuer" @update:model-value="reload" /></v-col>
      <v-col cols="12" md="5"><v-text-field v-model="filter.spiffe_id" label="SPIFFE ID contains" density="compact" clearable data-test="cert-filter-spiffe" @keyup.enter="reload" @click:clear="reload" /></v-col>
    </v-row>
    <v-alert v-if="store.error" type="error" variant="tonal" density="compact" class="mb-3">{{ store.error }}</v-alert>
    <v-table data-test="certificates-table">
      <thead>
        <tr><th>Identity</th><th>Kind</th><th>Serial</th><th>Status</th><th>Not after</th></tr>
      </thead>
      <tbody>
        <tr v-for="c in store.items" :key="c.id" class="cursor-pointer" :data-test="'cert-row-' + c.id" @click="open(c)">
          <td class="text-truncate" style="max-width: 300px">{{ c.spiffe_id || (c.sans && c.sans.length ? c.sans.join(', ') : '') || c.subject || '—' }}</td>
          <td><v-chip size="x-small" :color="c.kind === 'generic' ? 'info' : 'primary'" variant="tonal">{{ c.kind === 'generic' ? 'generic' : 'SVID' }}</v-chip></td>
          <td class="text-no-wrap">{{ c.serial ?? '—' }}</td>
          <td><v-chip size="x-small" :color="chipColor(c.status)" variant="tonal" :data-test="'cert-status-' + c.id">{{ c.status }}</v-chip></td>
          <td class="text-no-wrap">{{ c.not_after ? new Date(c.not_after).toLocaleDateString() : '—' }}</td>
        </tr>
        <tr v-if="!store.items.length && !store.loading"><td colspan="5" class="text-medium-emphasis">No certificates.</td></tr>
      </tbody>
    </v-table>
    <div v-if="store.next" class="mt-3 text-center">
      <v-btn variant="text" data-test="cert-more" @click="store.list({ status: filter.status ?? undefined, issuer_id: filter.issuer_id ?? undefined, spiffe_id: filter.spiffe_id || undefined }, store.next)">Load more</v-btn>
    </div>
    <CertificateDrawer v-model="drawer" :certificate="selected" @changed="reload" />
    <IssueDialog v-model="issue" />
    <v-snackbar v-model="snack.show" :color="snack.color" :timeout="6000" location="bottom right" data-test="cert-snack">{{ snack.text }}</v-snackbar>
  </div>
</template>

<style scoped>
.cursor-pointer { cursor: pointer; }
</style>
