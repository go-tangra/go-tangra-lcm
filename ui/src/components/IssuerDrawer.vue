<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { useIssuers } from '@/stores/issuers'
import { describe } from '@/api/client'
import { SET_MARKER, type DnsProviderField, type Issuer, type IssuerInput, type IssuerType, type Settings } from '@/api/types'

const model = defineModel<boolean>({ required: true })
const props = defineProps<{ issuer: Issuer | null }>()
const emit = defineEmits<{ saved: [Issuer]; removed: [string] }>()
const store = useIssuers()

const types: IssuerType[] = ['self_signed', 'acme']
const form = reactive({
  name: '',
  type: 'self_signed' as IssuerType,
  trust_domain: '',
  is_default: false,
  key_type: 'ecdsa-p256',
  validity_ceiling_days: 90,
  // acme
  directory: 'https://acme-v02.api.letsencrypt.org/directory',
  email: '',
  dns_provider: '',
  eab_kid: '',
})
// Write-only EAB HMAC key (external account binding); SET_MARKER means unchanged.
const eabHmac = ref('')
// Write-only credential values keyed by field key.
const creds = reactive<Record<string, string>>({})
const editing = computed(() => !!props.issuer)
const err = ref('')
const busy = ref(false)

const providers = computed(() => Array.isArray(store.dnsProviders) ? store.dnsProviders : [])
const providerFields = computed<DnsProviderField[]>(() => providers.value.find((p) => p.name === form.dns_provider)?.fields ?? [])

watch(
  () => [model.value, props.issuer] as const,
  async ([open]) => {
    if (!open) return
    err.value = ''
    await store.loadDnsProviders()
    const i = props.issuer
    const s = (i?.settings ?? {}) as Record<string, unknown>
    form.name = i?.name ?? ''
    form.type = i?.type ?? 'self_signed'
    form.trust_domain = i?.trust_domain ?? ''
    form.is_default = i?.is_default ?? false
    form.key_type = String(s.key_type ?? 'ecdsa-p256')
    form.validity_ceiling_days = Number(s.validity_ceiling_days ?? 90)
    form.directory = String(s.directory ?? 'https://acme-v02.api.letsencrypt.org/directory')
    form.email = String(s.email ?? '')
    form.dns_provider = String(s.dns_provider ?? '')
    form.eab_kid = String(s.eab_kid ?? '')
    eabHmac.value = s.eab_hmac_key ? SET_MARKER : ''
    for (const k of Object.keys(creds)) delete creds[k]
    // A stored secret shows the marker so it round-trips unchanged.
    for (const f of providerFields.value) if (f.secret) creds[f.key] = SET_MARKER
  },
  { immediate: true },
)

watch(
  () => form.dns_provider,
  () => {
    for (const k of Object.keys(creds)) delete creds[k]
    for (const f of providerFields.value) if (f.secret && editing.value) creds[f.key] = SET_MARKER
  },
)

function settings(): Settings {
  if (form.type === 'self_signed') return { key_type: form.key_type, validity_ceiling_days: form.validity_ceiling_days }
  return { key_type: form.key_type, validity_ceiling_days: form.validity_ceiling_days, directory: form.directory, email: form.email, dns_provider: form.dns_provider, eab_kid: form.eab_kid }
}

function secrets(): Record<string, unknown> | undefined {
  if (form.type !== 'acme') return undefined
  const out: Record<string, unknown> = {}
  for (const f of providerFields.value) {
    const v = creds[f.key]
    // Only send changed secrets; the marker (unchanged) is dropped.
    if (v !== undefined && v !== '' && v !== SET_MARKER) out[f.key] = v
  }
  // EAB HMAC key: send only when the operator entered a new value.
  if (eabHmac.value && eabHmac.value !== SET_MARKER) out.eab_hmac_key = eabHmac.value
  return Object.keys(out).length ? out : undefined
}

async function save(): Promise<void> {
  busy.value = true
  err.value = ''
  try {
    const input: IssuerInput = { name: form.name, type: form.type, trust_domain: form.trust_domain, is_default: form.is_default, settings: settings() }
    const sec = secrets()
    if (sec) input.secrets = sec
    const saved = props.issuer ? await store.update(props.issuer.id, input) : await store.create(input)
    emit('saved', saved)
    model.value = false
  } catch (e) {
    err.value = describe(e)
  } finally {
    busy.value = false
  }
}

async function remove(): Promise<void> {
  if (!props.issuer) return
  busy.value = true
  err.value = ''
  try {
    await store.remove(props.issuer.id)
    emit('removed', props.issuer.id)
    model.value = false
  } catch (e) {
    err.value = describe(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <v-navigation-drawer v-model="model" location="right" temporary width="480" data-test="issuer-drawer">
    <v-card flat>
      <v-card-title>{{ editing ? 'Edit issuer' : 'New issuer' }}</v-card-title>
      <v-card-text>
        <v-text-field v-model="form.name" label="Name" density="compact" data-test="issuer-name" />
        <v-select v-model="form.type" :items="types" label="Type" density="compact" :disabled="editing" data-test="issuer-type" />
        <v-text-field v-model="form.trust_domain" label="Trust domain" density="compact" :disabled="editing" data-test="issuer-trust-domain" />
        <v-select v-model="form.key_type" :items="['ecdsa-p256', 'ecdsa-p384', 'rsa-2048', 'rsa-4096']" label="Key type" density="compact" data-test="issuer-key-type" />
        <v-text-field v-model.number="form.validity_ceiling_days" label="Validity ceiling (days)" type="number" density="compact" data-test="issuer-validity" />
        <template v-if="form.type === 'acme'">
          <v-divider class="my-3" />
          <div class="text-subtitle-2 mb-2">ACME</div>
          <v-text-field v-model="form.directory" label="Directory URL" density="compact" data-test="issuer-acme-directory" />
          <v-text-field v-model="form.email" label="Account email" density="compact" data-test="issuer-acme-email" />
          <v-select
            v-model="form.dns_provider"
            :items="providers.map((p) => ({ title: p.display_name, value: p.name }))"
            label="DNS provider"
            density="compact"
            data-test="issuer-dns-provider"
          />
          <template v-for="f in providerFields" :key="f.key">
            <v-text-field
              v-model="creds[f.key]"
              :label="f.label + (f.required ? '' : ' (optional)')"
              :type="f.secret ? 'password' : 'text'"
              :hint="f.secret ? 'Leave “__set__” to keep the stored value.' : ''"
              persistent-hint
              density="compact"
              :data-test="'issuer-cred-' + f.key"
            />
          </template>
          <v-alert v-if="!providers.length" type="info" variant="tonal" density="compact" class="mt-2">No DNS providers are configured on this deployment.</v-alert>
          <div class="text-subtitle-2 mt-4 mb-2">External Account Binding (optional)</div>
          <p class="text-caption text-medium-emphasis mb-2">Required by some CAs (ZeroSSL, Google, Sectigo). Leave blank for Let's Encrypt / Pebble.</p>
          <v-text-field v-model="form.eab_kid" label="EAB Key ID (KID)" density="compact" data-test="issuer-eab-kid" />
          <v-text-field
            v-model="eabHmac"
            label="EAB HMAC key (base64url)"
            type="password"
            hint="Leave “__set__” to keep the stored key."
            persistent-hint
            density="compact"
            data-test="issuer-eab-hmac"
          />
        </template>
        <v-switch v-model="form.is_default" label="Default for this trust domain" density="compact" color="primary" data-test="issuer-default" />
        <v-alert v-if="err" type="error" variant="tonal" density="compact" data-test="issuer-error">{{ err }}</v-alert>
      </v-card-text>
      <v-card-actions>
        <v-btn v-if="editing && props.issuer?.permissions?.delete" color="error" variant="text" data-test="issuer-delete" @click="remove">Delete</v-btn>
        <v-spacer />
        <v-btn @click="model = false">Cancel</v-btn>
        <v-btn color="primary" :loading="busy" data-test="issuer-save" @click="save">Save</v-btn>
      </v-card-actions>
    </v-card>
  </v-navigation-drawer>
</template>
