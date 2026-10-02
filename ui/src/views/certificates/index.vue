<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { RouterLink, useRoute } from 'vue-router'
import { UiPage, UiAlert, UiCard, UiForm, UiInput, UiSelect, UiNumberInput, UiSwitch, UiTextarea, UiFilePicker, UiButton, UiDataTable, UiStatusChip, UiBadge, UiTabs, UiDrawer, UiKeyValueTable, useToast, useConfirm, useListQuery, type Column, type SelectOption, type TabItem } from '@go-tangra/ui'
import { useZodForm } from '@go-tangra/ui/forms'
import { useCertificates } from '@/stores/certificates'
import CertificateDetails from './CertificateDetails.vue'
import { useIssuers } from '@/stores/issuers'
import { useDirectory } from '@/stores/directory'
import { useLive } from '@/stores/live'
import { CERTIFICATE_LIST } from '@/stores/paged'
import { describe } from '@/api/client'
import { saveText } from '@/api/download'
import { certificateFilterSchema, issueSvidSchema, issueAcmeSchema, importCertSchema, revokeSchema, CERTIFICATE_STATUSES, trustDomainLabel } from '@/schemas'
import type { Certificate, CertificateBundle, CertificateFilter, ImportRenewal } from '@/api/types'

const store = useCertificates()
const issuers = useIssuers()
const directory = useDirectory()
const live = useLive()
const toast = useToast()
const confirm = useConfirm()

const statusOptions: SelectOption[] = CERTIFICATE_STATUSES.map((s) => ({ title: s, value: s }))
const issuerOptions = computed<SelectOption[]>(() => issuers.options.map((i) => ({ title: i.name, value: i.id })))

// --- server paging and sorting (page / size / sort in the URL: ?certificates.page=…) ---
const lq = useListQuery('certificates', CERTIFICATE_LIST.opts)
let current: CertificateFilter = {}
async function load(): Promise<void> {
  const res = await store.list(current, lq.query.value)
  if (res?.page) lq.clampTo(res.page) // a page beyond the end answers the last page
}
watch(lq.query, () => void load())
const filter = useZodForm(certificateFilterSchema, {
  initial: { spiffe_id: '' },
  onSubmit: async (f) => {
    current = { status: f.status, issuer_id: f.issuer_id || undefined, spiffe_id: f.spiffe_id || undefined }
    // A filter change starts at page 1 (which reloads), else reload in place.
    if (lq.page.value !== 1) lq.resetPage()
    else await load()
  },
})
const apply = () => void filter.submit()
const reload = () => void load()

let release: (() => void) | null = null
let offLive: (() => void) | null = null
const route = useRoute()
const linkError = ref('')
onMounted(() => {
  reload() // the page / size / sort of the URL apply as they are
  void issuers.loadOptions()
  // Deep link (e.g. from an issued ACME request): open that certificate.
  const id = route.query.id
  if (typeof id === 'string' && id) {
    store.get(id).then(open, (e) => (linkError.value = describe(e)))
  }
  // The shared SSE stream keeps the list live; async ACME issuance reports its outcome here.
  release = live.connect()
  offLive = live.on((type, data) => {
    if (type === 'certificate.issued') {
      const d = (data ?? {}) as { subject?: string }
      toast.success('Certificate issued', d.subject)
    } else if (type === 'certificate.failed') {
      const d = (data ?? {}) as { domains?: string[]; error?: string }
      toast.error('Certificate issuance failed', [d.domains?.length ? 'for ' + d.domains.join(', ') : '', d.error ?? ''].filter(Boolean).join(': '))
    }
  })
})
onUnmounted(() => {
  release?.()
  offLive?.()
})

const statusColors = { expiring: 'warning', expired: 'neutral' } as const
const identity = (c: Certificate) => c.spiffe_id || (c.sans?.length ? c.sans.join(', ') : '') || c.subject || c.serial || c.id
const columns: Column<Certificate>[] = [
  { key: 'identity', label: 'Identity', format: identity, sortable: true },
  { key: 'kind', label: 'Kind', width: 'sm', format: (c) => (c.kind === 'generic' ? 'generic' : 'SVID'), sortable: true },
  { key: 'serial', label: 'Serial', hideOnStack: true },
  { key: 'status', label: 'Status', width: 'sm', sortable: true },
  { key: 'not_after', label: 'Not after', format: (c) => (c.not_after ? new Date(c.not_after).toLocaleDateString() : ''), sortable: true },
  { key: 'created_at', label: 'Issued', format: (c) => (c.created_at ? new Date(c.created_at).toLocaleDateString() : ''), sortable: true, hideOnStack: true },
]

// --- request drawer: SVID (mesh) or ACME (public), one schema each ---
const issueOpen = ref(false)
const mode = ref('svid')
const queued = ref(false)
const modeTabs: TabItem[] = [{ key: 'svid', label: 'SVID (mesh)' }, { key: 'acme', label: 'ACME / public' }, { key: 'import', label: 'Import' }]
const svidIssuers = computed<SelectOption[]>(() => issuers.options.filter((i) => i.type !== 'acme').map((i) => ({ title: i.name + ' (' + trustDomainLabel(i.trust_domain) + ')', value: i.id })))
const acmeIssuers = computed<SelectOption[]>(() => issuers.options.filter((i) => i.type === 'acme').map((i) => ({ title: i.name + ' (' + trustDomainLabel(i.trust_domain) + ')', value: i.id })))
const svid = useZodForm(issueSvidSchema, {
  onSubmit: (v) => store.issue({ spiffe_id: v.spiffe_id, issuer_id: v.issuer_id, subject: v.subject, dns_sans: v.dns_sans.length ? v.dns_sans : undefined, validity_seconds: v.validity_days > 0 ? v.validity_days * 86400 : undefined, csr_pem: v.csr_pem }),
  onSuccess: () => (queued.value = true),
})
const acme = useZodForm(issueAcmeSchema, {
  onSubmit: (v) => store.obtainAcme({ issuer_id: v.issuer_id, domains: v.domains, auto_renew: v.auto_renew, csr_pem: v.csr_pem }),
  onSuccess: () => (queued.value = true),
})
// Import of a certificate issued by an ACME CA elsewhere (certbot layout):
// stored under the ACME issuer and renewed by lcm, keeping the key.
const imported = ref<ImportRenewal | null>(null)
const importForm = useZodForm(importCertSchema, {
  onSubmit: async (v) => {
    const r = await store.importCertificate({ issuer_id: v.issuer_id, cert_pem: v.cert_pem, chain_pem: v.chain_pem, key_pem: v.key_pem, auto_renew: v.auto_renew })
    imported.value = r.renewal
  },
  onSuccess: () => (queued.value = true),
})
const PEM_MAX_BYTES = 65536
/** Loads a chosen PEM file into its form field (the textarea stays editable). */
async function loadPem(field: 'cert_pem' | 'chain_pem' | 'key_pem', file: File | null): Promise<void> {
  if (!file) return
  importForm.values[field] = await file.text()
}
const currentForm = computed(() => (mode.value === 'acme' ? acme : mode.value === 'import' ? importForm : svid))
function openIssue(): void {
  mode.value = 'svid'
  queued.value = false
  svid.reset({ issuer_id: '', spiffe_id: '', subject: '', dns_sans: '', validity_days: 30, csr_pem: '' })
  acme.reset({ issuer_id: '', domains: '', auto_renew: true, csr_pem: '' })
  importForm.reset({ issuer_id: '', cert_pem: '', chain_pem: '', key_pem: '', auto_renew: true })
  imported.value = null
  issueOpen.value = true
}
watch(issueOpen, (o) => { if (!o && queued.value) reload() })

// --- detail drawer ---
const drawer = ref(false)
const selected = ref<Certificate | null>(null)
// decodedTitle is the drawer header from the certificate itself; the record's identity shows only until it is decoded.
const decodedTitle = ref('')
const error = ref('')
const busy = ref(false)
const bundle = ref<CertificateBundle | null>(null)
const showRevoke = ref(false)
const revokeForm = useZodForm(revokeSchema, {
  initial: { reason: '' },
  onSubmit: (v) => store.revoke(selected.value!.id, v.reason),
  onSuccess: () => {
    drawer.value = false
    reload()
  },
})
function open(c: Certificate): void {
  selected.value = c
  decodedTitle.value = ''
  error.value = ''
  bundle.value = null
  showRevoke.value = false
  revokeForm.reset({ reason: '' })
  if (c.owner) void directory.resolveUsers([c.owner])
  drawer.value = true
}
const canManage = computed(() => selected.value?.permissions?.write ?? false)
const canRevoke = computed(() => canManage.value && selected.value?.status !== 'revoked')
const meta = computed(() => {
  const c = selected.value
  if (!c) return []
  // Only record-level facts here: the certificate's own fields (subject,
  // serial, validity, SANs, fingerprints) are decoded from the certificate
  // bytes by CertificateDetails, never taken from the record's columns.
  return [{ label: 'Owner', value: directory.userName(c.owner) }]
})
async function run(fn: () => Promise<void>): Promise<void> {
  busy.value = true
  error.value = ''
  try {
    await fn()
  } catch (e) {
    error.value = describe(e)
  } finally {
    busy.value = false
  }
}
const download = (kind: 'cert' | 'chain' | 'bundle') => run(async () => {
  const c = selected.value!
  bundle.value ??= await store.download(c.id)
  const pem = kind === 'cert' ? bundle.value.cert_pem : kind === 'chain' ? bundle.value.chain_pem : bundle.value.bundle_pem
  if (!pem) {
    error.value = 'That artifact is not available for this certificate.'
    return
  }
  saveText(pem, (c.serial ?? c.id) + '-' + kind + '.pem', 'application/x-pem-file')
})
const downloadKey = () => run(async () => {
  const c = selected.value!
  saveText(await store.downloadKey(c.id), (c.serial ?? c.id) + '-key.pem', 'application/x-pem-file')
})
const toggleAutoRenew = (v: unknown) => run(async () => {
  await store.update(selected.value!.id, { auto_renew: !!v })
  reload()
})
const renew = async () => {
  if (!(await confirm.ask({ title: 'Renew now?', text: 'A new certificate replaces the current one.', confirmLabel: 'Renew' }))) return
  await run(async () => {
    await store.renew(selected.value!.id)
    drawer.value = false
    reload()
  })
}
</script>

<template>
  <UiPage title="Certificates">
    <template #actions><UiButton icon="mdi-plus" data-test="cert-issue-open" @click="openIssue">Request</UiButton></template>
    <template #filters>
      <UiForm :form="filter" class="w-full">
        <div class="grid grid-cols-2 gap-2 md:grid-cols-12 md:items-end">
          <div class="md:col-span-3"><UiSelect v-bind="filter.field('status')" label="Status" :options="statusOptions" size="sm" data-test="cert-filter-status" @update:model-value="apply" /></div>
          <div class="md:col-span-4"><UiSelect v-bind="filter.field('issuer_id')" label="Issuer" :options="issuerOptions" size="sm" data-test="cert-filter-issuer" @update:model-value="apply" /></div>
          <div class="col-span-2 md:col-span-5"><UiInput v-bind="filter.field('spiffe_id')" label="SPIFFE ID" type="search" size="sm" data-test="cert-filter-spiffe" @enter="apply" /></div>
        </div>
      </UiForm>
    </template>
    <UiAlert v-if="store.error" kind="error" class="mb-3">{{ store.error }}</UiAlert>
    <UiAlert v-if="linkError" kind="error" class="mb-3" data-test="cert-link-error">{{ linkError }}</UiAlert>
    <UiCard :padded="false">
      <UiDataTable :items="store.items" :columns="columns" :loading="store.loading" :total="store.total" :page="lq.page.value" :page-size="lq.pageSize.value" :sort="lq.sort.value" caption="Certificates" empty-title="No certificates" clickable :row-attrs="(c) => ({ 'data-test': 'cert-row-' + c.id })" data-test="certificates-table" @row-click="open" @update:page="lq.setPage" @update:page-size="lq.setPageSize" @update:sort="lq.setSort">
        <template #cell-kind="{ row }"><UiBadge :color="row.kind === 'generic' ? 'info' : 'primary'">{{ row.kind === 'generic' ? 'generic' : 'SVID' }}</UiBadge></template>
        <template #cell-status="{ row }"><UiStatusChip :status="row.status" :colors="statusColors" :data-test="'cert-status-' + row.id" /></template>
      </UiDataTable>
    </UiCard>

    <UiDrawer v-model="issueOpen" title="Request certificate" size="lg" data-test="issue-dialog">
      <template v-if="!queued">
        <UiTabs v-model="mode" :tabs="modeTabs" class="mb-4" data-test="issue-mode" />
        <UiForm v-if="mode === 'svid'" :form="svid">
          <div class="flex flex-col gap-3">
            <UiSelect v-bind="svid.field('issuer_id')" label="Issuer (defaults to the trust domain default)" :options="svidIssuers" data-test="issue-issuer" />
            <UiInput v-bind="svid.field('spiffe_id')" label="SPIFFE ID" placeholder="spiffe://example.org/service/api" required data-test="issue-spiffe" />
            <UiInput v-bind="svid.field('subject')" label="Subject (optional)" data-test="issue-subject" />
            <UiInput v-bind="svid.field('dns_sans')" label="DNS SANs (comma-separated, optional)" data-test="issue-sans" />
            <UiNumberInput v-bind="svid.field('validity_days')" label="Validity (days)" :min="0" :max="3650" data-test="issue-validity" />
            <UiTextarea v-bind="svid.field('csr_pem')" label="CSR PEM (optional; leave blank to generate a key pair)" :rows="3" hint="When a key pair is generated, it is retained and downloadable from the certificate afterwards." data-test="issue-csr" />
          </div>
        </UiForm>
        <UiForm v-else-if="mode === 'acme'" :form="acme">
          <div class="flex flex-col gap-3">
            <UiSelect v-bind="acme.field('issuer_id')" label="ACME issuer" :options="acmeIssuers" :placeholder="acmeIssuers.length ? '—' : 'No ACME issuers. Add one under Issuers.'" required data-test="issue-acme-issuer" />
            <UiInput v-bind="acme.field('domains')" label="Domains (comma-separated)" placeholder="example.com, www.example.com" hint="Validity is set by the ACME provider. DNS-01 is solved with the issuer's configured DNS provider." required data-test="issue-domains" />
            <UiSwitch v-bind="acme.field('auto_renew')" label="Auto-renew before expiry" data-test="issue-auto-renew" />
            <UiTextarea v-bind="acme.field('csr_pem')" label="CSR PEM (optional; leave blank to generate a key pair)" :rows="3" data-test="issue-csr" />
          </div>
        </UiForm>
        <UiForm v-else :form="importForm">
          <div class="flex flex-col gap-3">
            <UiAlert kind="info">Bring a certificate issued by an ACME CA elsewhere (for example certbot). lcm keeps the key, renews the certificate for the same domains through the chosen issuer's ACME account and DNS provider, and serves it like one it issued.</UiAlert>
            <UiSelect v-bind="importForm.field('issuer_id')" label="ACME issuer that renews it" :options="acmeIssuers" :placeholder="acmeIssuers.length ? '—' : 'No ACME issuers. Add one under Issuers.'" required data-test="import-issuer" />
            <UiFilePicker id="import-cert-file" label="Certificate file" accept=".pem,.crt,.cer" :max-bytes="PEM_MAX_BYTES" hint="fullchain.pem or cert.pem" data-test="import-cert-file" @update:model-value="(f) => loadPem('cert_pem', f)" />
            <UiTextarea v-bind="importForm.field('cert_pem')" label="Certificate PEM (leaf first, chain may follow)" :rows="4" required data-test="import-cert" />
            <UiFilePicker id="import-chain-file" label="Chain file (optional)" accept=".pem,.crt,.cer" :max-bytes="PEM_MAX_BYTES" hint="chain.pem, when the certificate file has no chain" data-test="import-chain-file" @update:model-value="(f) => loadPem('chain_pem', f)" />
            <UiTextarea v-bind="importForm.field('chain_pem')" label="Chain PEM (optional)" :rows="3" data-test="import-chain" />
            <UiFilePicker id="import-key-file" label="Private key file" accept=".pem,.key" :max-bytes="PEM_MAX_BYTES" hint="privkey.pem (unencrypted RSA or ECDSA)" data-test="import-key-file" @update:model-value="(f) => loadPem('key_pem', f)" />
            <UiTextarea v-bind="importForm.field('key_pem')" label="Private key PEM" :rows="4" required data-test="import-key" />
            <UiSwitch v-bind="importForm.field('auto_renew')" label="Auto-renew before expiry" data-test="import-auto-renew" />
          </div>
        </UiForm>
      </template>
      <UiAlert v-else-if="mode === 'import'" :kind="imported === 'off' ? 'info' : 'success'" data-test="import-done">
        Certificate imported.
        <template v-if="imported === 'started'">It was already due for renewal, so an ACME renewal is running now; the renewed certificate appears in the list, or an error is shown if it fails.</template>
        <template v-else-if="imported === 'scheduled'">lcm renews it automatically before it expires.</template>
        <template v-else>Auto-renew is off; renew it from the certificate when needed.</template>
      </UiAlert>
      <UiAlert v-else-if="mode === 'acme'" kind="info" data-test="issue-queued">ACME order submitted and processing. It is recorded under <RouterLink to="/lcm/requests" class="link" data-test="issue-requests-link">Requests</RouterLink>, where it ends issued or failed with the CA's reason; the certificate appears in this list when issued.</UiAlert>
      <UiAlert v-else kind="info" data-test="issue-queued">Certificate requested. Issuance runs in the background — it will appear in the list when issued, or an error will be shown if it fails.</UiAlert>
      <template #actions>
        <template v-if="!queued">
          <UiButton variant="text" @click="issueOpen = false">Cancel</UiButton>
          <UiButton :loading="currentForm.submitting.value" data-test="issue-submit" @click="currentForm.submit()">{{ mode === 'acme' ? 'Request' : mode === 'import' ? 'Import' : 'Issue' }}</UiButton>
        </template>
        <UiButton v-else data-test="issue-done" @click="issueOpen = false">Done</UiButton>
      </template>
    </UiDrawer>

    <UiDrawer v-model="drawer" :title="decodedTitle || (selected ? identity(selected) : '')" size="lg" data-test="certificate-drawer">
      <template v-if="selected">
        <div class="mb-3 flex flex-wrap gap-1"><UiStatusChip :status="selected.status" :colors="statusColors" data-test="cert-status" /><UiBadge :color="selected.kind === 'generic' ? 'info' : 'primary'" data-test="cert-kind">{{ selected.kind === 'generic' ? 'generic' : 'SVID' }}</UiBadge></div>
        <UiKeyValueTable :items="meta" />
        <CertificateDetails :certificate-id="selected.id" @title="decodedTitle = $event" />
        <UiSwitch id="cert-auto-renew" :model-value="selected.auto_renew ?? false" :disabled="!canManage || busy" label="Auto-renew before expiry" class="mt-3" data-test="cert-auto-renew" @update:model-value="toggleAutoRenew" />
        <h3 class="mb-2 mt-4 text-sm font-medium">Download</h3>
        <div class="flex flex-wrap gap-2">
          <UiButton size="sm" variant="soft" :loading="busy" icon="mdi-file-certificate-outline" data-test="cert-download-cert" @click="download('cert')">Certificate</UiButton>
          <UiButton size="sm" variant="soft" :loading="busy" icon="mdi-link-variant" data-test="cert-download-chain" @click="download('chain')">Chain</UiButton>
          <UiButton size="sm" variant="soft" :loading="busy" icon="mdi-package-variant-closed" data-test="cert-download-bundle" @click="download('bundle')">Bundle</UiButton>
          <UiButton v-if="selected.has_key" size="sm" variant="soft" color="warning" :loading="busy" icon="mdi-key-variant" data-test="cert-download-key" @click="downloadKey">Private key</UiButton>
        </div>
        <UiAlert v-if="error" kind="error" class="mt-3" data-test="cert-error">{{ error }}</UiAlert>
        <UiForm v-if="showRevoke" :form="revokeForm" class="mt-4 rounded-box border border-error/40 p-3">
          <UiInput v-bind="revokeForm.field('reason')" label="Revocation reason (optional)" data-test="cert-revoke-reason" />
          <UiButton color="error" size="sm" class="mt-2" :loading="revokeForm.submitting.value" data-test="cert-revoke-confirm" @click="revokeForm.submit()">Confirm revoke</UiButton>
        </UiForm>
      </template>
      <template #actions>
        <UiButton v-if="canRevoke" variant="text" color="error" data-test="cert-revoke" @click="showRevoke = true">Revoke</UiButton>
        <UiButton v-if="canManage" variant="text" :loading="busy" data-test="cert-renew" @click="renew">Renew</UiButton>
        <UiButton @click="drawer = false">Close</UiButton>
      </template>
    </UiDrawer>
  </UiPage>
</template>
