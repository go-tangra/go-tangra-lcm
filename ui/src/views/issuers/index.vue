<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { UiPage, UiAlert, UiCard, UiButton, UiDataTable, UiBadge, UiIcon, UiDrawer, UiForm, UiInput, UiSelect, UiNumberInput, UiSwitch, UiSecretField, UiSection, useConfirm, type Column, type SelectOption } from '@freya/ui'
import { useZodForm } from '@freya/ui/forms'
import { useIssuers } from '@/stores/issuers'
import { describe } from '@/api/client'
import { issuerSchema, ISSUER_TYPES, KEY_TYPES, providerHint } from '@/schemas'
import { SET_MARKER, type Issuer, type IssuerInput } from '@/api/types'

const store = useIssuers()
const confirm = useConfirm()
const drawer = ref(false)
const selected = ref<Issuer | null>(null)
const error = ref('')
onMounted(() => {
  void store.list()
  void store.loadDnsProviders()
})
const typeOptions: SelectOption[] = ISSUER_TYPES.map((t) => ({ title: t, value: t }))
const keyOptions: SelectOption[] = KEY_TYPES.map((k) => ({ title: k, value: k }))
const providers = computed(() => (Array.isArray(store.dnsProviders) ? store.dnsProviders : []))
const providerOptions = computed<SelectOption[]>(() => providers.value.map((p) => ({ title: p.display_name, value: p.name })))

const form = useZodForm(issuerSchema, {
  onSubmit: async (v) => {
    // Only changed secrets travel; blanks and the stored marker are dropped by the schema.
    const secrets: Record<string, unknown> = {}
    for (const [k, val] of Object.entries(v.credentials)) if (val && val !== SET_MARKER) secrets[k] = val
    if (v.eab_hmac_key) secrets.eab_hmac_key = v.eab_hmac_key
    const settings = v.type === 'acme' ? { key_type: v.key_type, validity_ceiling_days: v.validity_ceiling_days, directory: v.directory, email: v.email, dns_provider: v.dns_provider, eab_kid: v.eab_kid ?? '' } : { key_type: v.key_type, validity_ceiling_days: v.validity_ceiling_days }
    const input: IssuerInput = { name: v.name, type: v.type, trust_domain: v.trust_domain, is_default: v.is_default, settings, ...(Object.keys(secrets).length ? { secrets } : {}) }
    if (selected.value) await store.update(selected.value.id, input)
    else await store.create(input)
  },
  onSuccess: () => {
    drawer.value = false
    void store.list()
  },
})
const isAcme = computed(() => form.values.type === 'acme')
const providerFields = computed(() => providers.value.find((p) => p.name === form.values.dns_provider)?.fields ?? [])
const dnsHint = computed(() => providerHint(String(form.values.dns_provider ?? '')))
const creds = computed(() => (form.values.credentials ?? {}) as Record<string, string>)
function setCred(key: string, v: unknown): void {
  form.values.credentials = { ...creds.value, [key]: String(v ?? '') }
}
// A stored secret shows the marker so it round-trips unchanged; switching providers clears the values.
watch(() => form.values.dns_provider, () => {
  const next: Record<string, string> = {}
  for (const f of providerFields.value) if (f.secret && selected.value) next[f.key] = SET_MARKER
  form.values.credentials = next
})
function open(i: Issuer | null): void {
  selected.value = i
  error.value = ''
  const s = (i?.settings ?? {}) as Record<string, unknown>
  const credentials: Record<string, string> = {}
  for (const f of providers.value.find((p) => p.name === String(s.dns_provider ?? ''))?.fields ?? []) if (f.secret) credentials[f.key] = SET_MARKER
  form.reset({ name: i?.name ?? '', type: i?.type ?? 'self_signed', trust_domain: i?.trust_domain ?? '', is_default: i?.is_default ?? false, key_type: (KEY_TYPES.includes(s.key_type as (typeof KEY_TYPES)[number]) ? s.key_type : 'ecdsa-p256') as (typeof KEY_TYPES)[number], validity_ceiling_days: Number(s.validity_ceiling_days ?? 90), directory: String(s.directory ?? 'https://acme-v02.api.letsencrypt.org/directory'), email: String(s.email ?? ''), dns_provider: String(s.dns_provider ?? ''), eab_kid: String(s.eab_kid ?? ''), eab_hmac_key: s.eab_hmac_key ? SET_MARKER : '', credentials })
  drawer.value = true
}
async function remove(): Promise<void> {
  if (!selected.value || !(await confirm.ask({ title: `Delete ${selected.value.name}?`, danger: true, confirmLabel: 'Delete' }))) return
  try {
    await store.remove(selected.value.id)
    drawer.value = false
    void store.list()
  } catch (e) {
    error.value = describe(e)
  }
}
const columns: Column<Issuer>[] = [
  { key: 'name', label: 'Name', sortable: true },
  { key: 'type', label: 'Type', width: 'sm' },
  { key: 'trust_domain', label: 'Trust domain' },
  { key: 'is_default', label: 'Default', width: 'sm', format: (i) => (i.is_default ? 'yes' : '') },
  { key: 'certificate_count', label: 'Certificates', align: 'end', format: (i) => String(i.certificate_count ?? 0) },
]
</script>

<template>
  <UiPage title="Issuers">
    <template #actions><UiButton icon="mdi-plus" data-test="issuer-new" @click="open(null)">New issuer</UiButton></template>
    <UiAlert v-if="store.error" kind="error" class="mb-3">{{ store.error }}</UiAlert>
    <UiCard :padded="false">
      <UiDataTable :items="store.items" :columns="columns" :loading="store.loading" caption="Issuers" empty-title="No issuers yet" clickable :row-attrs="(i) => ({ 'data-test': 'issuer-row-' + i.id })" data-test="issuers-table" @row-click="open">
        <template #cell-type="{ row }"><UiBadge>{{ row.type }}</UiBadge></template>
        <template #cell-is_default="{ row }"><UiIcon v-if="row.is_default" name="mdi-star" size="sm" class="text-warning" label="Default issuer" /></template>
      </UiDataTable>
    </UiCard>
    <UiDrawer v-model="drawer" :title="selected ? 'Edit issuer' : 'New issuer'" size="lg" data-test="issuer-drawer">
      <UiAlert v-if="error" kind="error" class="mb-3" data-test="issuer-error">{{ error }}</UiAlert>
      <UiForm :form="form">
        <div class="flex flex-col gap-3">
          <UiInput v-bind="form.field('name')" label="Name" required data-test="issuer-name" />
          <UiSelect v-bind="form.field('type')" label="Type" :options="typeOptions" :clearable="false" :disabled="!!selected" required data-test="issuer-type" />
          <UiInput v-bind="form.field('trust_domain')" label="Trust domain" :disabled="!!selected" required data-test="issuer-trust-domain" />
          <UiSelect v-bind="form.field('key_type')" label="Key type" :options="keyOptions" :clearable="false" required data-test="issuer-key-type" />
          <UiNumberInput v-bind="form.field('validity_ceiling_days')" label="Validity ceiling (days)" :min="1" :max="3650" required data-test="issuer-validity" />
          <UiSection v-if="isAcme" title="ACME">
            <div class="flex flex-col gap-3">
              <UiInput v-bind="form.field('directory')" label="Directory URL" type="url" required data-test="issuer-acme-directory" />
              <UiInput v-bind="form.field('email')" label="Account email" type="email" required data-test="issuer-acme-email" />
              <UiSelect v-bind="form.field('dns_provider')" label="DNS provider" :options="providerOptions" required data-test="issuer-dns-provider" />
              <UiAlert v-if="!providers.length" kind="info">No DNS providers are configured on this deployment.</UiAlert>
              <UiAlert v-if="dnsHint" kind="info" data-test="issuer-dns-hint">{{ dnsHint }}</UiAlert>
              <template v-for="f in providerFields" :key="f.key">
                <UiSecretField v-if="f.secret" :id="'cred-' + f.key" :model-value="creds[f.key] ?? ''" :label="f.label + (f.required ? '' : ' (optional)')" hint="Leave “__set__” to keep the stored value." :data-test="'issuer-cred-' + f.key" @update:model-value="setCred(f.key, $event)" />
                <UiInput v-else :id="'cred-' + f.key" :model-value="creds[f.key] ?? ''" :label="f.label + (f.required ? '' : ' (optional)')" :data-test="'issuer-cred-' + f.key" @update:model-value="setCred(f.key, $event)" />
              </template>
            </div>
          </UiSection>
          <UiSection v-if="isAcme" title="External Account Binding (optional)" description="Required by some CAs (ZeroSSL, Google, Sectigo). Leave blank for Let's Encrypt / Pebble.">
            <div class="flex flex-col gap-3">
              <UiInput v-bind="form.field('eab_kid')" label="EAB Key ID (KID)" data-test="issuer-eab-kid" />
              <UiSecretField v-bind="form.field('eab_hmac_key')" label="EAB HMAC key (base64url)" hint="Leave “__set__” to keep the stored key." data-test="issuer-eab-hmac" />
            </div>
          </UiSection>
          <UiSwitch v-bind="form.field('is_default')" label="Default for this trust domain" data-test="issuer-default" />
        </div>
      </UiForm>
      <template #actions>
        <UiButton v-if="selected && selected.permissions?.delete" variant="text" color="error" data-test="issuer-delete" @click="remove">Delete</UiButton>
        <UiButton variant="text" @click="drawer = false">Cancel</UiButton>
        <UiButton :loading="form.submitting.value" data-test="issuer-save" @click="form.submit()">Save</UiButton>
      </template>
    </UiDrawer>
  </UiPage>
</template>
