<script setup lang="ts">
// The "Certificate" section of the certificate drawer. Every value shown here
// is decoded server-side from the stored certificate bytes (crypto/x509) —
// never from the record's columns or the original request.
//
// Layout: an always-visible summary card (identity, validity status and
// timeline, key/CA chips) above tabs that group the full decode into cards.
import { computed, ref, watch } from 'vue'
import { UiAlert, UiBadge, UiButton, UiCard, UiCopyButton, UiIcon, UiSkeleton, UiTabs } from '@go-tangra/ui'
import { useCertificates } from '@/stores/certificates'
import { describe as describeError } from '@/api/client'
import type { CertificateDetails, CertificateDetailsResult } from '@/api/types'
import { durationLabel, elapsedPercent, expiryBadge, hexGroups, isWebURL, keyLabel, parseDN, shortHex, validityState, widthClass, type BadgeColor } from './certDetailsFormat'

const props = defineProps<{ certificateId: string }>()
// title reports the decoded name (subject CN, else first SAN) so the drawer header shows it; '' until decoded or when unavailable.
const emit = defineEmits<{ title: [value: string] }>()
const store = useCertificates()

const loading = ref(false)
const error = ref('')
const result = ref<CertificateDetailsResult | null>(null)
const now = ref(Date.now())
let seq = 0

async function load(): Promise<void> {
  const mine = ++seq
  loading.value = true
  error.value = ''
  result.value = null
  try {
    const r = await store.details(props.certificateId)
    if (mine === seq) {
      now.value = Date.now()
      result.value = r
    }
  } catch (e) {
    if (mine === seq) error.value = describeError(e)
  } finally {
    if (mine === seq) loading.value = false
  }
}
watch(() => props.certificateId, () => void load(), { immediate: true })

const d = computed<CertificateDetails | null>(() => (result.value?.available ? (result.value.details ?? null) : null))

/** A date-time in the viewer's locale and time zone (as elsewhere in lcm); the ISO/UTC value is the tooltip. */
const when = (iso: string) => new Date(iso).toLocaleString()
const day = (iso: string) => new Date(iso).toLocaleDateString()

// ---- summary ---------------------------------------------------------------

const state = computed(() => (d.value ? validityState(d.value.validity, now.value) : null))
const tints: Record<BadgeColor, string> = { success: 'bg-success/10 text-success', warning: 'bg-warning/10 text-warning', error: 'bg-error/10 text-error', info: 'bg-info/10 text-info' }
const fills: Record<BadgeColor, string> = { success: 'bg-success', warning: 'bg-warning', error: 'bg-error', info: 'bg-info' }

const title = computed(() => {
  const x = d.value
  if (!x) return ''
  const s = x.sans
  return x.subject.cn || s.dns[0] || s.ip[0] || s.uri[0] || s.email[0] || x.subject.dn || 'Unnamed certificate'
})
watch(title, (t) => emit('title', t), { immediate: true })
const issuedBy = computed(() => {
  const x = d.value
  if (!x) return ''
  return x.self_signed ? 'Self-signed' : 'Issued by ' + (x.issuer.cn || x.issuer.dn || 'an unnamed issuer')
})
const elapsed = computed(() => (d.value ? elapsedPercent(d.value.validity.not_before, d.value.validity.not_after, now.value) : 0))

// ---- tabs ------------------------------------------------------------------

type TabKey = 'cert-overview' | 'cert-names' | 'cert-key' | 'cert-extensions' | 'cert-fingerprints' | 'cert-chain'
// Kept while switching certificates in the drawer.
const tab = ref<TabKey>('cert-overview')

const sanGroups = computed(() => {
  const s = d.value?.sans
  if (!s) return []
  // SPIFFE IDs are URIs too; show them once, under their own heading.
  const spiffe = new Set(s.spiffe)
  return [
    { key: 'dns', label: 'DNS names', items: s.dns },
    { key: 'ip', label: 'IP addresses', items: s.ip },
    { key: 'spiffe', label: 'SPIFFE IDs', items: s.spiffe },
    { key: 'uri', label: 'URIs', items: s.uri.filter((u) => !spiffe.has(u)) },
    { key: 'email', label: 'Email addresses', items: s.email },
  ].filter((g) => g.items.length > 0)
})
const sanCount = computed(() => sanGroups.value.reduce((n, g) => n + g.items.length, 0))

interface ChainItem { key: string; role: string; subject: string; issuer: string; notAfter: string; fingerprint: string; badge: { label: string; color: BadgeColor } }
const chain = computed<ChainItem[]>(() => {
  const x = d.value
  if (!x) return []
  const leaf: ChainItem = {
    key: 'leaf',
    role: 'This certificate',
    subject: title.value,
    issuer: x.issuer.cn || x.issuer.dn,
    notAfter: x.validity.not_after,
    fingerprint: x.fingerprints.sha256,
    badge: state.value ? { label: state.value.label, color: state.value.color } : expiryBadge(x.validity.not_after, now.value),
  }
  return [
    leaf,
    ...x.chain.map((c, i) => ({
      key: c.fingerprint_sha256 + i,
      role: c.subject.dn === c.issuer.dn ? 'Root' : 'Intermediate',
      subject: c.subject.cn || c.subject.dn,
      issuer: c.issuer.cn || c.issuer.dn,
      notAfter: c.not_after,
      fingerprint: c.fingerprint_sha256,
      badge: expiryBadge(c.not_after, now.value),
    })),
  ]
})

const tabs = computed(() => [
  { key: 'cert-overview', label: 'Overview' },
  { key: 'cert-names', label: 'Names', count: sanCount.value },
  { key: 'cert-key', label: 'Key & usage' },
  { key: 'cert-extensions', label: 'Extensions' },
  { key: 'cert-fingerprints', label: 'Fingerprints' },
  { key: 'cert-chain', label: 'Chain', count: chain.value.length },
])
const selectTab = (k: string) => (tab.value = k as TabKey)

// ---- tab content -----------------------------------------------------------

const names = computed(() => {
  const x = d.value
  if (!x) return []
  return [
    { key: 'subject', title: 'Subject', icon: 'mdi-certificate-outline', parts: parseDN(x.subject.dn), dn: x.subject.dn },
    { key: 'issuer', title: 'Issuer', icon: 'mdi-domain', parts: parseDN(x.issuer.dn), dn: x.issuer.dn },
  ]
})

const publicKey = computed(() => (d.value ? keyLabel(d.value.public_key) : ''))

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
    { key: 'crl', label: 'CRL distribution points', items: x.crl_distribution_points },
    { key: 'ocsp', label: 'OCSP responders', items: x.ocsp_servers },
    { key: 'issuers', label: 'CA issuers', items: x.issuing_certificate_urls },
  ]
})

const fingerprints = computed(() => {
  const f = d.value?.fingerprints
  if (!f) return []
  return [
    { key: 'sha256', label: 'SHA-256', value: f.sha256 },
    { key: 'sha1', label: 'SHA-1', value: f.sha1 },
  ]
})

// Shared card styling, so every card in the section reads the same.
const heading = 'mb-2 flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-base-content/70'
const row = 'grid grid-cols-1 gap-x-3 @md:grid-cols-[9.5rem_minmax(0,1fr)] border-b border-base-300/60 py-1.5 last:border-0'
const label = 'text-base-content/70'
const value = 'min-w-0 break-words'
const none = 'text-sm text-base-content/60'
const mono = 'min-w-0 grow break-all font-mono text-xs leading-5'
</script>

<template>
  <section class="mt-4" aria-labelledby="cert-details-heading" data-test="cert-details">
    <h3 id="cert-details-heading" class="text-sm font-medium">Certificate</h3>
    <p class="mb-3 text-xs text-base-content/70" data-test="cert-details-caption">Read from the certificate itself (X.509), not from the request or the stored record.</p>

    <UiSkeleton v-if="loading" kind="text" :lines="6" data-test="cert-details-loading" />

    <UiAlert v-else-if="error" kind="error" data-test="cert-details-error">
      Certificate details could not be loaded: {{ error }}
      <UiButton size="sm" variant="text" icon="mdi-refresh" class="ml-2" data-test="cert-details-retry" @click="load">Retry</UiButton>
    </UiAlert>

    <UiAlert v-else-if="result && !result.available" kind="warning" data-test="cert-details-unavailable">
      The stored certificate could not be decoded{{ result.reason ? ': ' + result.reason : '.' }}
    </UiAlert>

    <div v-else-if="d && state" class="flex flex-col gap-3 text-sm">
      <!-- Summary: always visible. -->
      <UiCard flat :padded="false" class="@container" data-test="cert-details-summary">
        <div class="flex flex-col gap-3 p-4">
          <div class="flex items-start gap-3">
            <span class="flex size-10 shrink-0 items-center justify-center rounded-full" :class="tints[state.color]"><UiIcon :name="state.icon" size="md" /></span>
            <div class="min-w-0 grow">
              <p class="truncate text-base font-semibold" :title="title" data-test="cert-details-title">{{ title }}</p>
              <p class="truncate text-sm text-base-content/70" :title="d.issuer.dn" data-test="cert-details-subtitle">{{ issuedBy }}</p>
            </div>
            <div class="flex shrink-0 flex-col items-end gap-1">
              <UiBadge :color="state.color" size="md" :data-state="state.key" data-test="cert-details-validity">{{ state.label }}</UiBadge>
              <span class="text-xs text-base-content/70" data-test="cert-details-validity-hint">{{ state.hint }}</span>
            </div>
          </div>

          <div class="flex flex-wrap gap-1.5" data-test="cert-details-chips">
            <UiBadge size="sm" color="info" data-test="cert-details-key-chip"><UiIcon name="mdi-key-variant" size="xs" class="me-1" />{{ publicKey }}</UiBadge>
            <UiBadge v-if="d.basic_constraints.ca" size="sm" color="primary" data-test="cert-details-ca-chip">CA</UiBadge>
            <UiBadge v-if="d.self_signed" size="sm" color="secondary" data-test="cert-details-self-signed-chip">Self-signed</UiBadge>
          </div>

          <div data-test="cert-details-timeline">
            <div class="h-2 w-full rounded-full bg-base-content/10" role="progressbar" aria-label="Validity period elapsed" aria-valuemin="0" aria-valuemax="100" :aria-valuenow="Math.round(elapsed)" :aria-valuetext="state.hint">
              <div class="relative h-full rounded-full" :class="[fills[state.color], widthClass(elapsed)]" data-test="cert-details-progress">
                <span v-if="state.key === 'valid' || state.key === 'expiring'" class="absolute -end-1.5 top-1/2 size-3 -translate-y-1/2 rounded-full border-2 border-base-100" :class="fills[state.color]" title="Today" data-test="cert-details-today" />
              </div>
            </div>
            <div class="mt-1.5 flex justify-between gap-2 text-xs text-base-content/70">
              <span :title="d.validity.not_before">From {{ day(d.validity.not_before) }}</span>
              <span :title="d.validity.not_after">Until {{ day(d.validity.not_after) }}</span>
            </div>
          </div>
        </div>
      </UiCard>

      <UiTabs :model-value="tab" :tabs="tabs" class="text-sm [&>.tab]:px-2" data-test="cert-details-tabs" @update:model-value="selectTab" />

      <div :id="'panel-' + tab" role="tabpanel" :aria-labelledby="'tab-' + tab" tabindex="0" class="flex flex-col gap-3 rounded-box focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary" :data-test="'cert-details-panel-' + tab.slice(5)">
        <!-- Overview -->
        <template v-if="tab === 'cert-overview'">
          <div class="flex flex-col gap-3">
            <UiCard v-for="n in names" :key="n.key" flat :padded="false" class="@container" :data-test="'cert-details-' + n.key">
              <div class="p-3">
                <h4 :class="heading"><UiIcon :name="n.icon" size="sm" />{{ n.title }}<UiBadge v-if="n.key === 'issuer' && d.self_signed" size="xs" color="secondary" class="ms-auto normal-case tracking-normal">self-signed</UiBadge></h4>
                <dl v-if="n.parts.length">
                  <div v-for="(p, i) in n.parts" :key="p.type + i" :class="row">
                    <dt :class="label" :title="p.type">{{ p.label }}</dt>
                    <dd :class="value" :data-test="n.key === 'subject' && p.type === 'CN' ? 'cert-details-subject-cn' : undefined">{{ p.value }}</dd>
                  </div>
                </dl>
                <p v-else :class="none">Empty distinguished name</p>
                <details v-if="n.dn" class="mt-2">
                  <summary class="cursor-pointer select-none text-xs text-base-content/70 hover:text-base-content">Full distinguished name</summary>
                  <p class="mt-1 break-all rounded-field bg-base-200 p-2 font-mono text-xs" :data-test="'cert-details-' + n.key + '-dn'">{{ n.dn }}</p>
                </details>
              </div>
            </UiCard>
          </div>
          <UiCard flat :padded="false" class="@container" data-test="cert-details-validity-card">
            <div class="p-3">
              <h4 :class="heading"><UiIcon name="mdi-calendar-clock" size="sm" />Validity</h4>
              <dl class="grid grid-cols-1 gap-3 @md:grid-cols-3">
                <div><dt :class="['text-xs', label]">Not before</dt><dd :class="value" :title="d.validity.not_before" data-test="cert-details-not-before">{{ when(d.validity.not_before) }}</dd></div>
                <div><dt :class="['text-xs', label]">Not after</dt><dd :class="value" :title="d.validity.not_after" data-test="cert-details-not-after">{{ when(d.validity.not_after) }}</dd></div>
                <div><dt :class="['text-xs', label]">Lifetime</dt><dd :class="value" data-test="cert-details-duration">{{ durationLabel(d.validity.not_before, d.validity.not_after) }}</dd></div>
              </dl>
            </div>
          </UiCard>
          <UiCard flat :padded="false" class="@container" data-test="cert-details-identity-card">
            <div class="p-3">
              <h4 :class="heading"><UiIcon name="mdi-information-outline" size="sm" />Serial number<UiBadge size="xs" class="normal-case tracking-normal" data-test="cert-details-version">X.509 v{{ d.version }}</UiBadge><UiCopyButton :value="d.serial" label="Copy" size="xs" class="ms-auto normal-case tracking-normal" data-test="cert-details-copy-serial" /></h4>
              <p class="rounded-field bg-base-200 px-3 py-2"><span class="break-all font-mono text-xs leading-5" data-test="cert-details-serial">{{ d.serial }}</span></p>
            </div>
          </UiCard>
        </template>

        <!-- Names (SANs) -->
        <template v-else-if="tab === 'cert-names'">
          <p v-if="!sanGroups.length" :class="none" data-test="cert-details-sans-none">None — this certificate has no subject alternative names.</p>
          <UiCard v-for="g in sanGroups" v-else :key="g.key" flat :padded="false" class="@container">
            <div class="p-3">
              <h4 :class="heading">{{ g.label }}<span class="badge badge-xs badge-soft">{{ g.items.length }}</span></h4>
              <ul class="divide-y divide-base-300/60" :data-test="'cert-details-san-' + g.key">
                <li v-for="v in g.items" :key="v" class="flex items-center gap-2 py-1"><span :class="mono">{{ v }}</span><UiCopyButton :value="v" label="" size="xs" :aria-label="'Copy ' + v" :title="'Copy ' + v" /></li>
              </ul>
            </div>
          </UiCard>
        </template>

        <!-- Key & usage -->
        <template v-else-if="tab === 'cert-key'">
          <div class="flex flex-col gap-3">
            <UiCard flat :padded="false" class="@container">
              <div class="p-3">
                <h4 :class="heading"><UiIcon name="mdi-key-variant" size="sm" />Public key</h4>
                <dl>
                  <div :class="row"><dt :class="label">Key</dt><dd :class="value" data-test="cert-details-public-key">{{ publicKey }}</dd></div>
                  <div :class="row"><dt :class="label">Algorithm</dt><dd :class="value">{{ d.public_key.algorithm }}</dd></div>
                  <div v-if="d.public_key.size" :class="row"><dt :class="label">Size</dt><dd :class="value">{{ d.public_key.size }} bit</dd></div>
                  <div v-if="d.public_key.curve" :class="row"><dt :class="label">Curve</dt><dd :class="value">{{ d.public_key.curve }}</dd></div>
                  <div :class="row"><dt :class="label">Signature</dt><dd :class="value" data-test="cert-details-signature">{{ d.signature_algorithm }}</dd></div>
                </dl>
              </div>
            </UiCard>
            <UiCard flat :padded="false" class="@container">
              <div class="p-3">
                <h4 :class="heading"><UiIcon name="mdi-shield-check-outline" size="sm" />Basic constraints</h4>
                <dl>
                  <div :class="row"><dt :class="label">Summary</dt><dd :class="value" data-test="cert-details-basic-constraints">{{ basicConstraints }}</dd></div>
                  <template v-if="d.basic_constraints.present">
                    <div :class="row"><dt :class="label">CA</dt><dd :class="value"><UiBadge size="xs" :color="d.basic_constraints.ca ? 'primary' : 'neutral'">{{ d.basic_constraints.ca ? 'Yes' : 'No' }}</UiBadge></dd></div>
                    <div v-if="d.basic_constraints.ca" :class="row"><dt :class="label">Path length</dt><dd :class="value">{{ d.basic_constraints.path_len === undefined ? 'Unlimited' : d.basic_constraints.path_len }}</dd></div>
                  </template>
                </dl>
              </div>
            </UiCard>
          </div>
          <UiCard flat :padded="false" class="@container">
            <div class="flex flex-col gap-3 p-3">
              <div>
                <h4 :class="heading">Key usage</h4>
                <div class="flex flex-wrap gap-1.5" data-test="cert-details-key-usage"><UiBadge v-for="k in d.key_usage" :key="k" size="sm" color="info">{{ k }}</UiBadge><span v-if="!d.key_usage.length" :class="none">None</span></div>
              </div>
              <div>
                <h4 :class="heading">Extended key usage</h4>
                <div class="flex flex-wrap gap-1.5" data-test="cert-details-eku"><UiBadge v-for="k in d.ext_key_usage" :key="k" size="sm" color="accent">{{ k }}</UiBadge><span v-if="!d.ext_key_usage.length" :class="none">None</span></div>
              </div>
            </div>
          </UiCard>
        </template>

        <!-- Extensions -->
        <template v-else-if="tab === 'cert-extensions'">
          <UiCard flat :padded="false" class="@container">
            <div class="p-3">
              <h4 :class="heading"><UiIcon name="mdi-key-outline" size="sm" />Key identifiers</h4>
              <dl v-if="d.subject_key_id || d.authority_key_id">
                <div v-if="d.subject_key_id" :class="row">
                  <dt :class="label">Subject key ID</dt>
                  <dd class="flex min-w-0 items-start gap-2"><span :class="mono" data-test="cert-details-ski">{{ d.subject_key_id }}</span><UiCopyButton :value="d.subject_key_id" label="" size="xs" aria-label="Copy subject key ID" title="Copy subject key ID" data-test="cert-details-copy-ski" /></dd>
                </div>
                <div v-if="d.authority_key_id" :class="row">
                  <dt :class="label">Authority key ID</dt>
                  <dd class="flex min-w-0 items-start gap-2"><span :class="mono" data-test="cert-details-aki">{{ d.authority_key_id }}</span><UiCopyButton :value="d.authority_key_id" label="" size="xs" aria-label="Copy authority key ID" title="Copy authority key ID" data-test="cert-details-copy-aki" /></dd>
                </div>
              </dl>
              <p v-else :class="none">None</p>
            </div>
          </UiCard>
          <UiCard flat :padded="false" class="@container">
            <div class="p-3">
              <h4 :class="heading"><UiIcon name="mdi-link-variant" size="sm" />Revocation and issuer access</h4>
              <dl>
                <div v-for="g in urls" :key="g.key" :class="row">
                  <dt :class="label">{{ g.label }}</dt>
                  <dd :class="value" :data-test="'cert-details-url-' + g.key">
                    <span v-if="!g.items.length" :class="none">None</span>
                    <template v-for="u in g.items" :key="u">
                      <a v-if="isWebURL(u)" :href="u" target="_blank" rel="noopener noreferrer" class="link link-hover link-primary block break-all font-mono text-xs leading-5">{{ u }}</a>
                      <span v-else class="block break-all font-mono text-xs leading-5">{{ u }}</span>
                    </template>
                  </dd>
                </div>
              </dl>
            </div>
          </UiCard>
        </template>

        <!-- Fingerprints -->
        <template v-else-if="tab === 'cert-fingerprints'">
          <UiCard v-for="f in fingerprints" :key="f.key" flat :padded="false" class="@container">
            <div class="p-3">
              <h4 :class="heading"><UiIcon name="mdi-lock-outline" size="sm" />{{ f.label }}<UiCopyButton :value="f.value" label="Copy" size="xs" class="ms-auto normal-case tracking-normal" :data-test="'cert-details-copy-' + f.key" /></h4>
              <p class="flex flex-wrap gap-x-2.5 gap-y-0.5 rounded-field bg-base-200 px-3 py-2 font-mono text-xs leading-6" :data-test="'cert-details-' + f.key"><span v-for="(grp, i) in hexGroups(f.value)" :key="i">{{ grp }}</span></p>
            </div>
          </UiCard>
        </template>

        <!-- Chain -->
        <template v-else-if="tab === 'cert-chain'">
          <ol class="flex flex-col" data-test="cert-details-chain">
            <li v-for="(c, i) in chain" :key="c.key" class="flex gap-3" :data-test="'cert-details-chain-' + i">
              <div class="flex w-3 shrink-0 flex-col items-center" aria-hidden="true">
                <span class="mt-4 size-3 shrink-0 rounded-full" :class="fills[c.badge.color]" />
                <span v-if="i < chain.length - 1" class="-mb-1 mt-1 w-0.5 grow rounded-full bg-base-content/15" />
              </div>
              <UiCard flat :padded="false" class="@container min-w-0 grow" :class="i < chain.length - 1 ? 'mb-3' : ''">
                <div class="flex flex-col gap-1 p-3">
                  <div class="flex flex-wrap items-center gap-2">
                    <span class="text-xs font-semibold uppercase tracking-wide text-base-content/70">{{ c.role }}</span>
                    <UiBadge size="xs" :color="c.badge.color" class="ms-auto" data-test="cert-details-chain-badge">{{ c.badge.label }}</UiBadge>
                  </div>
                  <p class="break-words font-medium" data-test="cert-details-chain-subject">{{ c.subject }}</p>
                  <p class="break-words text-xs text-base-content/70">Issued by {{ c.issuer }} · expires <span :title="c.notAfter">{{ when(c.notAfter) }}</span></p>
                  <div class="flex items-center gap-2">
                    <span class="min-w-0 truncate font-mono text-xs text-base-content/70" :title="c.fingerprint">SHA-256 {{ shortHex(c.fingerprint) }}</span>
                    <UiCopyButton :value="c.fingerprint" label="" size="xs" :aria-label="'Copy SHA-256 fingerprint of ' + c.subject" title="Copy SHA-256 fingerprint" :data-test="'cert-details-copy-chain-' + i" />
                  </div>
                </div>
              </UiCard>
            </li>
          </ol>
          <UiAlert v-if="d.chain_error" kind="warning" data-test="cert-details-chain-error">{{ d.chain_error }}</UiAlert>
          <p v-else-if="chain.length === 1" :class="none" data-test="cert-details-chain-none">No chain certificates are stored with this certificate.</p>
        </template>
      </div>
    </div>
  </section>
</template>
