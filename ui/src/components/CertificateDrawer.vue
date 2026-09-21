<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useCertificates } from '@/stores/certificates'
import { useDirectory } from '@/stores/directory'
import { describe } from '@/api/client'
import { saveText } from '@/api/download'
import type { Certificate, CertificateBundle } from '@/api/types'

const model = defineModel<boolean>({ required: true })
const props = defineProps<{ certificate: Certificate | null }>()
const emit = defineEmits<{ changed: [] }>()
const store = useCertificates()
const directory = useDirectory()

const err = ref('')
const busy = ref(false)
const revokeReason = ref('')
const showRevoke = ref(false)
const bundle = ref<CertificateBundle | null>(null)

const isGeneric = computed(() => props.certificate?.kind === 'generic')
const identity = computed(() => {
  const c = props.certificate
  if (!c) return ''
  return c.spiffe_id || (c.sans && c.sans.length ? c.sans.join(', ') : '') || c.subject || c.serial || c.id
})
const ownerName = computed(() => directory.userName(props.certificate?.owner))
const canManage = computed(() => props.certificate?.permissions?.write ?? false)
const canRevoke = computed(() => (props.certificate?.permissions?.write ?? false) && props.certificate?.status !== 'revoked')

watch(
  () => [model.value, props.certificate] as const,
  ([open]) => {
    if (!open) return
    err.value = ''
    showRevoke.value = false
    revokeReason.value = ''
    bundle.value = null
    if (props.certificate?.owner) void directory.resolveUsers([props.certificate.owner])
  },
)

async function download(kind: 'cert' | 'chain' | 'bundle'): Promise<void> {
  if (!props.certificate) return
  busy.value = true
  err.value = ''
  try {
    bundle.value ??= await store.download(props.certificate.id)
    const b = bundle.value
    const pem = kind === 'cert' ? b.cert_pem : kind === 'chain' ? b.chain_pem : b.bundle_pem
    if (!pem) {
      err.value = 'That artifact is not available for this certificate.'
      return
    }
    saveText(pem, props.certificate.serial ?? props.certificate.id + '-' + kind + '.pem', 'application/x-pem-file')
  } catch (e) {
    err.value = describe(e)
  } finally {
    busy.value = false
  }
}

async function toggleAutoRenew(v: boolean | null): Promise<void> {
  if (!props.certificate) return
  busy.value = true
  err.value = ''
  try {
    await store.update(props.certificate.id, { auto_renew: !!v })
    emit('changed')
  } catch (e) {
    err.value = describe(e)
  } finally {
    busy.value = false
  }
}

async function downloadKey(): Promise<void> {
  if (!props.certificate) return
  busy.value = true
  err.value = ''
  try {
    const keyPem = await store.downloadKey(props.certificate.id)
    saveText(keyPem, (props.certificate.serial ?? props.certificate.id) + '-key.pem', 'application/x-pem-file')
  } catch (e) {
    err.value = describe(e)
  } finally {
    busy.value = false
  }
}

async function renew(): Promise<void> {
  if (!props.certificate) return
  busy.value = true
  err.value = ''
  try {
    await store.renew(props.certificate.id)
    emit('changed')
    model.value = false
  } catch (e) {
    err.value = describe(e)
  } finally {
    busy.value = false
  }
}

async function revoke(): Promise<void> {
  if (!props.certificate) return
  busy.value = true
  err.value = ''
  try {
    await store.revoke(props.certificate.id, revokeReason.value || undefined)
    emit('changed')
    model.value = false
  } catch (e) {
    err.value = describe(e)
  } finally {
    busy.value = false
  }
}

function chipColor(status: string): string {
  return status === 'active' ? 'success' : status === 'expiring' ? 'warning' : status === 'revoked' ? 'error' : 'grey'
}
</script>

<template>
  <v-navigation-drawer v-model="model" location="right" temporary width="520" data-test="certificate-drawer">
    <v-card v-if="props.certificate" flat>
      <v-card-title class="text-truncate">{{ identity }}</v-card-title>
      <v-card-text>
        <v-chip size="small" :color="chipColor(props.certificate.status)" variant="tonal" class="mb-3 mr-2" data-test="cert-status">{{ props.certificate.status }}</v-chip>
        <v-chip size="small" :color="isGeneric ? 'info' : 'primary'" variant="tonal" class="mb-3" data-test="cert-kind">{{ isGeneric ? 'generic' : 'SVID' }}</v-chip>
        <v-table density="compact">
          <tbody>
            <tr><td class="text-medium-emphasis">Serial</td><td class="text-no-wrap">{{ props.certificate.serial ?? '—' }}</td></tr>
            <tr><td class="text-medium-emphasis">Subject</td><td>{{ props.certificate.subject ?? '—' }}</td></tr>
            <tr><td class="text-medium-emphasis">Not before</td><td>{{ props.certificate.not_before ? new Date(props.certificate.not_before).toLocaleString() : '—' }}</td></tr>
            <tr><td class="text-medium-emphasis">Not after</td><td>{{ props.certificate.not_after ? new Date(props.certificate.not_after).toLocaleString() : '—' }}</td></tr>
            <tr><td class="text-medium-emphasis">Fingerprint</td><td class="text-caption text-break">{{ props.certificate.fingerprint_sha256 ?? '—' }}</td></tr>
            <tr><td class="text-medium-emphasis">Owner</td><td>{{ ownerName || '—' }}</td></tr>
          </tbody>
        </v-table>
        <div v-if="props.certificate.sans?.length" class="mt-2">
          <div class="text-caption text-medium-emphasis">SANs</div>
          <v-chip v-for="s in props.certificate.sans" :key="s" size="x-small" variant="tonal" class="mr-1 mb-1">{{ s }}</v-chip>
        </div>
        <v-switch
          :model-value="props.certificate.auto_renew ?? false"
          :disabled="!canManage || busy"
          label="Auto-renew before expiry"
          density="compact"
          color="primary"
          hide-details
          class="mt-2"
          data-test="cert-auto-renew"
          @update:model-value="toggleAutoRenew"
        />
        <v-divider class="my-3" />
        <div class="text-subtitle-2 mb-2">Download</div>
        <div class="d-flex ga-2 flex-wrap">
          <v-btn size="small" variant="tonal" :loading="busy" prepend-icon="mdi-file-certificate-outline" data-test="cert-download-cert" @click="download('cert')">Certificate</v-btn>
          <v-btn size="small" variant="tonal" :loading="busy" prepend-icon="mdi-link-variant" data-test="cert-download-chain" @click="download('chain')">Chain</v-btn>
          <v-btn size="small" variant="tonal" :loading="busy" prepend-icon="mdi-package-variant-closed" data-test="cert-download-bundle" @click="download('bundle')">Bundle</v-btn>
          <v-btn v-if="props.certificate.has_key" size="small" variant="tonal" color="warning" :loading="busy" prepend-icon="mdi-key-variant" data-test="cert-download-key" @click="downloadKey">Private key</v-btn>
        </div>
        <v-alert v-if="err" type="error" variant="tonal" density="compact" class="mt-3" data-test="cert-error">{{ err }}</v-alert>
        <template v-if="showRevoke">
          <v-divider class="my-3" />
          <v-text-field v-model="revokeReason" label="Revocation reason (optional)" density="compact" data-test="cert-revoke-reason" />
          <v-btn color="error" size="small" :loading="busy" data-test="cert-revoke-confirm" @click="revoke">Confirm revoke</v-btn>
        </template>
      </v-card-text>
      <v-card-actions>
        <v-btn v-if="canRevoke" color="error" variant="text" data-test="cert-revoke" @click="showRevoke = true">Revoke</v-btn>
        <v-btn v-if="canManage" variant="text" :loading="busy" data-test="cert-renew" @click="renew">Renew</v-btn>
        <v-spacer />
        <v-btn @click="model = false">Close</v-btn>
      </v-card-actions>
    </v-card>
  </v-navigation-drawer>
</template>
