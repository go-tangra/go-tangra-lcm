<script setup lang="ts">
// The "Certificate" section of the certificate drawer. Every value shown here
// is decoded server-side from the stored certificate bytes (crypto/x509) —
// never from the record's columns or the original request.
import { computed, ref, watch } from 'vue'
import { UiAlert, UiBadge, UiButton, UiCopyButton, UiSkeleton } from '@go-tangra/ui'
import { useCertificates } from '@/stores/certificates'
import { describe as describeError } from '@/api/client'
import type { CertificateDetails, CertificateDetailsResult } from '@/api/types'

const props = defineProps<{ certificateId: string }>()
const store = useCertificates()

const loading = ref(false)
const error = ref('')
const result = ref<CertificateDetailsResult | null>(null)
let seq = 0

async function load(): Promise<void> {
  const mine = ++seq
  loading.value = true
  error.value = ''
  result.value = null
  try {
    const r = await store.details(props.certificateId)
    if (mine === seq) result.value = r
  } catch (e) {
    if (mine === seq) error.value = describeError(e)
  } finally {
    if (mine === seq) loading.value = false
  }
}
watch(() => props.certificateId, () => void load(), { immediate: true })

const d = computed<CertificateDetails | null>(() => (result.value?.available ? (result.value.details ?? null) : null))

/** A date-time in the viewer's locale and time zone (as elsewhere in lcm). */
const when = (iso: string) => new Date(iso).toLocaleString()

const validity = computed(() => {
  const v = d.value?.validity
  if (!v) return null
  const n = Math.abs(v.days_remaining)
  const days = n === 1 ? '1 day' : n + ' days'
  if (v.status === 'expired') return { color: 'error' as const, label: 'Expired', hint: n === 0 ? 'expired today' : 'expired ' + days + ' ago' }
  if (v.status === 'not_yet_valid') return { color: 'warning' as const, label: 'Not yet valid', hint: 'starts ' + when(v.not_before) }
  return { color: (v.days_remaining < 30 ? 'warning' : 'success') as 'warning' | 'success', label: 'Valid', hint: v.days_remaining === 0 ? 'expires within a day' : days + ' remaining' }
})

const sanGroups = computed(() => {
  const s = d.value?.sans
  if (!s) return []
  // SPIFFE IDs are URIs too; show them once, under their own heading.
  const spiffe = new Set(s.spiffe)
  return [
    { key: 'dns', label: 'DNS', items: s.dns },
    { key: 'ip', label: 'IP', items: s.ip },
    { key: 'spiffe', label: 'SPIFFE ID', items: s.spiffe },
    { key: 'uri', label: 'URI', items: s.uri.filter((u) => !spiffe.has(u)) },
    { key: 'email', label: 'Email', items: s.email },
  ].filter((g) => g.items.length > 0)
})

const publicKey = computed(() => {
  const k = d.value?.public_key
  if (!k) return ''
  return [k.algorithm, k.size ? k.size + ' bit' : '', k.curve ?? ''].filter(Boolean).join(' · ')
})

const basicConstraints = computed(() => {
  const b = d.value?.basic_constraints
  if (!b || !b.present) return 'Not present'
  if (!b.ca) return 'End entity (CA: false)'
  return 'CA: true · path length ' + (b.path_len === undefined ? 'unlimited' : String(b.path_len))
})

const urls = computed(() => {
  const x = d.value
  if (!x) return []
  return [
    { label: 'CRL distribution points', items: x.crl_distribution_points },
    { label: 'OCSP', items: x.ocsp_servers },
    { label: 'CA issuers', items: x.issuing_certificate_urls },
  ].filter((g) => g.items.length > 0)
})
</script>

<template>
  <section class="mt-4" aria-labelledby="cert-details-heading" data-test="cert-details">
    <div class="flex flex-wrap items-baseline justify-between gap-2">
      <h3 id="cert-details-heading" class="text-sm font-medium">Certificate</h3>
      <UiBadge v-if="validity" :color="validity.color" size="sm" soft data-test="cert-details-validity">{{ validity.label }} · {{ validity.hint }}</UiBadge>
    </div>
    <p class="mb-2 text-xs text-base-content/70" data-test="cert-details-caption">Read from the certificate itself (X.509), not from the request or the stored record.</p>

    <UiSkeleton v-if="loading" kind="text" :lines="6" data-test="cert-details-loading" />

    <UiAlert v-else-if="error" kind="error" data-test="cert-details-error">
      Certificate details could not be loaded: {{ error }}
      <UiButton size="sm" variant="text" icon="mdi-refresh" class="ml-2" data-test="cert-details-retry" @click="load">Retry</UiButton>
    </UiAlert>

    <UiAlert v-else-if="result && !result.available" kind="warning" data-test="cert-details-unavailable">
      The stored certificate could not be decoded{{ result.reason ? ': ' + result.reason : '.' }}
    </UiAlert>

    <div v-else-if="d" class="flex flex-col gap-4 text-sm">
      <dl class="grid grid-cols-1 gap-x-4 gap-y-1.5 sm:grid-cols-[minmax(7rem,max-content)_minmax(0,1fr)] [&>dd]:min-w-0 [&>dd]:max-sm:mb-1 [&>dt]:text-base-content/70">
        <dt>Common name</dt>
        <dd data-test="cert-details-subject-cn">{{ d.subject.cn || '—' }}</dd>
        <dt>Subject</dt>
        <dd class="break-all font-mono text-xs" data-test="cert-details-subject-dn">{{ d.subject.dn || '—' }}</dd>
        <dt>Issuer</dt>
        <dd data-test="cert-details-issuer">
          <span class="block">{{ d.issuer.cn || '—' }}<UiBadge v-if="d.self_signed" size="xs" class="ml-2">self-signed</UiBadge></span>
          <span class="block break-all font-mono text-xs text-base-content/70">{{ d.issuer.dn }}</span>
        </dd>
        <dt>Serial</dt>
        <dd class="flex items-start gap-2"><span class="min-w-0 break-all font-mono text-xs" data-test="cert-details-serial">{{ d.serial }}</span><UiCopyButton :value="d.serial" label="Copy" size="xs" data-test="cert-details-copy-serial" /></dd>
        <dt>Version</dt>
        <dd>v{{ d.version }}</dd>
        <dt>Not before</dt>
        <dd :title="d.validity.not_before" data-test="cert-details-not-before">{{ when(d.validity.not_before) }}</dd>
        <dt>Not after</dt>
        <dd :title="d.validity.not_after" data-test="cert-details-not-after">{{ when(d.validity.not_after) }}</dd>
      </dl>

      <div>
        <h4 class="mb-1 text-xs font-medium uppercase tracking-wide text-base-content/70">Subject alternative names</h4>
        <p v-if="!sanGroups.length" class="text-base-content/70">None</p>
        <dl v-else class="grid grid-cols-1 gap-x-4 gap-y-1.5 sm:grid-cols-[minmax(7rem,max-content)_minmax(0,1fr)] [&>dd]:min-w-0 [&>dd]:max-sm:mb-1 [&>dt]:text-base-content/70" data-test="cert-details-sans">
          <template v-for="g in sanGroups" :key="g.key">
            <dt>{{ g.label }}</dt>
            <dd class="flex flex-wrap gap-1" :data-test="'cert-details-san-' + g.key"><UiBadge v-for="v in g.items" :key="v" size="xs" outline class="break-all">{{ v }}</UiBadge></dd>
          </template>
        </dl>
      </div>

      <div>
        <h4 class="mb-1 text-xs font-medium uppercase tracking-wide text-base-content/70">Key and extensions</h4>
        <dl class="grid grid-cols-1 gap-x-4 gap-y-1.5 sm:grid-cols-[minmax(7rem,max-content)_minmax(0,1fr)] [&>dd]:min-w-0 [&>dd]:max-sm:mb-1 [&>dt]:text-base-content/70">
          <dt>Public key</dt>
          <dd data-test="cert-details-public-key">{{ publicKey }}</dd>
          <dt>Signature</dt>
          <dd data-test="cert-details-signature">{{ d.signature_algorithm }}</dd>
          <dt>Key usage</dt>
          <dd class="flex flex-wrap gap-1" data-test="cert-details-key-usage"><UiBadge v-for="k in d.key_usage" :key="k" size="xs">{{ k }}</UiBadge><span v-if="!d.key_usage.length" class="text-base-content/70">—</span></dd>
          <dt>Extended key usage</dt>
          <dd class="flex flex-wrap gap-1" data-test="cert-details-eku"><UiBadge v-for="k in d.ext_key_usage" :key="k" size="xs">{{ k }}</UiBadge><span v-if="!d.ext_key_usage.length" class="text-base-content/70">—</span></dd>
          <dt>Basic constraints</dt>
          <dd data-test="cert-details-basic-constraints">{{ basicConstraints }}</dd>
          <template v-if="d.subject_key_id">
            <dt>Subject key ID</dt>
            <dd class="flex items-start gap-2"><span class="min-w-0 break-all font-mono text-xs" data-test="cert-details-ski">{{ d.subject_key_id }}</span><UiCopyButton :value="d.subject_key_id" label="Copy" size="xs" /></dd>
          </template>
          <template v-if="d.authority_key_id">
            <dt>Authority key ID</dt>
            <dd class="flex items-start gap-2"><span class="min-w-0 break-all font-mono text-xs" data-test="cert-details-aki">{{ d.authority_key_id }}</span><UiCopyButton :value="d.authority_key_id" label="Copy" size="xs" /></dd>
          </template>
          <template v-for="g in urls" :key="g.label">
            <dt>{{ g.label }}</dt>
            <dd class="break-all font-mono text-xs"><span v-for="u in g.items" :key="u" class="block">{{ u }}</span></dd>
          </template>
        </dl>
      </div>

      <div>
        <h4 class="mb-1 text-xs font-medium uppercase tracking-wide text-base-content/70">Fingerprints</h4>
        <dl class="grid grid-cols-1 gap-x-4 gap-y-1.5 sm:grid-cols-[minmax(7rem,max-content)_minmax(0,1fr)] [&>dd]:min-w-0 [&>dd]:max-sm:mb-1 [&>dt]:text-base-content/70">
          <dt>SHA-256</dt>
          <dd class="flex items-start gap-2"><span class="min-w-0 break-all font-mono text-xs" data-test="cert-details-sha256">{{ d.fingerprints.sha256 }}</span><UiCopyButton :value="d.fingerprints.sha256" label="Copy" size="xs" data-test="cert-details-copy-sha256" /></dd>
          <dt>SHA-1</dt>
          <dd class="flex items-start gap-2"><span class="min-w-0 break-all font-mono text-xs" data-test="cert-details-sha1">{{ d.fingerprints.sha1 }}</span><UiCopyButton :value="d.fingerprints.sha1" label="Copy" size="xs" data-test="cert-details-copy-sha1" /></dd>
        </dl>
      </div>

      <div v-if="d.chain.length || d.chain_error">
        <h4 class="mb-1 text-xs font-medium uppercase tracking-wide text-base-content/70">Chain</h4>
        <ol class="flex flex-col gap-2" data-test="cert-details-chain">
          <li v-for="(c, i) in d.chain" :key="c.fingerprint_sha256 + i" class="rounded-box border border-base-content/15 p-2">
            <span class="block font-medium">{{ c.subject.cn || c.subject.dn }}</span>
            <span class="block text-xs text-base-content/70">issued by {{ c.issuer.cn || c.issuer.dn }} · expires <span :title="c.not_after">{{ when(c.not_after) }}</span></span>
            <span class="block break-all font-mono text-xs text-base-content/70">{{ c.fingerprint_sha256 }}</span>
          </li>
        </ol>
        <UiAlert v-if="d.chain_error" kind="warning" class="mt-2" data-test="cert-details-chain-error">{{ d.chain_error }}</UiAlert>
      </div>
    </div>
  </section>
</template>

