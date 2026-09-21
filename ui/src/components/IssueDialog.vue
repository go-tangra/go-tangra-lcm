<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { useCertificates } from '@/stores/certificates'
import { useIssuers } from '@/stores/issuers'
import { describe } from '@/api/client'
import type { AcmeInput, IssueInput } from '@/api/types'

const model = defineModel<boolean>({ required: true })
const certs = useCertificates()
const issuers = useIssuers()

// 'svid' = mesh SPIFFE identity; 'acme' = generic public cert via an ACME issuer.
const mode = ref<'svid' | 'acme'>('svid')

const form = reactive({
  issuer_id: '',
  spiffe_id: '',
  subject: '',
  dns_sans: '',
  validity_days: 30,
  csr_pem: '',
  domains: '',
  auto_renew: true,
})
const err = ref('')
const busy = ref(false)
// Issuance is asynchronous: after submit we show a "requested" acknowledgement
// and the certificate arrives in the list over SSE (or a failure toast).
const queued = ref(false)

// ACME certificates can only be minted from an ACME-type issuer.
const acmeIssuers = computed(() => issuers.items.filter((i) => i.type === 'acme'))
const svidIssuers = computed(() => issuers.items.filter((i) => i.type !== 'acme'))

function resetForm(): void {
  err.value = ''
  queued.value = false
  form.issuer_id = ''
  form.spiffe_id = ''
  form.subject = ''
  form.dns_sans = ''
  form.validity_days = 30
  form.csr_pem = ''
  form.domains = ''
  form.auto_renew = true
}

watch(
  () => model.value,
  async (open) => {
    if (!open) return
    mode.value = 'svid'
    resetForm()
    if (!issuers.items.length) await issuers.list()
  },
)
watch(mode, () => {
  form.issuer_id = ''
  err.value = ''
})

async function submit(): Promise<void> {
  busy.value = true
  err.value = ''
  try {
    if (mode.value === 'acme') {
      const domains = form.domains.split(',').map((s) => s.trim()).filter(Boolean)
      if (!form.issuer_id) throw new Error('Select an ACME issuer.')
      if (!domains.length) throw new Error('Enter at least one domain.')
      const input: AcmeInput = { issuer_id: form.issuer_id, domains, auto_renew: form.auto_renew }
      if (form.csr_pem.trim()) input.csr_pem = form.csr_pem
      await certs.obtainAcme(input)
    } else {
      const input: IssueInput = { spiffe_id: form.spiffe_id }
      if (form.issuer_id) input.issuer_id = form.issuer_id
      if (form.subject) input.subject = form.subject
      if (form.dns_sans.trim()) input.dns_sans = form.dns_sans.split(',').map((s) => s.trim()).filter(Boolean)
      if (form.validity_days > 0) input.validity_seconds = form.validity_days * 86400
      if (form.csr_pem.trim()) input.csr_pem = form.csr_pem
      await certs.issue(input)
    }
    queued.value = true
  } catch (e) {
    err.value = describe(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <v-dialog v-model="model" max-width="560" data-test="issue-dialog">
    <v-card>
      <v-card-title>Request certificate</v-card-title>
      <v-card-text v-if="!queued">
        <v-btn-toggle v-model="mode" mandatory density="compact" color="primary" class="mb-4" data-test="issue-mode">
          <v-btn value="svid" data-test="issue-mode-svid">SVID (mesh)</v-btn>
          <v-btn value="acme" data-test="issue-mode-acme">ACME / public</v-btn>
        </v-btn-toggle>

        <!-- Mesh SVID -->
        <template v-if="mode === 'svid'">
          <v-select
            v-model="form.issuer_id"
            :items="svidIssuers.map((i) => ({ title: i.name + ' (' + i.trust_domain + ')', value: i.id }))"
            label="Issuer (defaults to the trust domain default)"
            density="compact"
            clearable
            data-test="issue-issuer"
          />
          <v-text-field v-model="form.spiffe_id" label="SPIFFE ID" placeholder="spiffe://example.org/service/api" density="compact" data-test="issue-spiffe" />
          <v-text-field v-model="form.subject" label="Subject (optional)" density="compact" data-test="issue-subject" />
          <v-text-field v-model="form.dns_sans" label="DNS SANs (comma-separated, optional)" density="compact" data-test="issue-sans" />
          <v-text-field v-model.number="form.validity_days" label="Validity (days)" type="number" density="compact" data-test="issue-validity" />
        </template>

        <!-- ACME / public generic cert -->
        <template v-else>
          <v-select
            v-model="form.issuer_id"
            :items="acmeIssuers.map((i) => ({ title: i.name + ' (' + i.trust_domain + ')', value: i.id }))"
            label="ACME issuer"
            density="compact"
            no-data-text="No ACME issuers. Add one under Issuers."
            data-test="issue-acme-issuer"
          />
          <v-text-field v-model="form.domains" label="Domains (comma-separated)" placeholder="example.com, www.example.com" density="compact" data-test="issue-domains" />
          <p class="text-caption text-medium-emphasis mb-2">Validity is set by the ACME provider. DNS-01 is solved with the issuer's configured DNS provider.</p>
          <v-switch v-model="form.auto_renew" label="Auto-renew before expiry" density="compact" color="primary" data-test="issue-auto-renew" />
        </template>

        <v-textarea v-model="form.csr_pem" label="CSR PEM (optional; leave blank to generate a key pair)" rows="3" density="compact" data-test="issue-csr" />
        <p class="text-caption text-medium-emphasis mb-2">When a key pair is generated, it is retained and downloadable from the certificate afterwards.</p>
        <v-alert v-if="err" type="error" variant="tonal" density="compact" data-test="issue-error">{{ err }}</v-alert>
      </v-card-text>
      <v-card-text v-else data-test="issue-queued">
        <v-alert type="info" variant="tonal" density="compact">
          Certificate requested. Issuance runs in the background — it will appear in the list when issued, or an error will be shown if it fails.
        </v-alert>
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn v-if="!queued" @click="model = false">Cancel</v-btn>
        <v-btn v-if="!queued" color="primary" :loading="busy" data-test="issue-submit" @click="submit">{{ mode === 'acme' ? 'Request' : 'Issue' }}</v-btn>
        <v-btn v-else color="primary" data-test="issue-done" @click="model = false">Done</v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>
