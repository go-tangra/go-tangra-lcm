<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { UiPage, UiAlert, UiCard, UiButton, UiDataTable, UiBadge, UiIcon, UiDrawer, UiForm, UiInput, UiSelect, UiTextarea, UiSecretField, useConfirm, type Column, type SelectOption } from '@freya/ui'
import { useZodForm } from '@freya/ui/forms'
import { useSecrets } from '@/stores/secrets'
import { describe } from '@/api/client'
import { secretSchema, webhookSchema, SECRET_KINDS } from '@/schemas'
import type { Secret, Webhook } from '@/api/types'

const store = useSecrets()
const confirm = useConfirm()
const drawer = ref(false)
const selected = ref<Secret | null>(null)
const error = ref('')
onMounted(async () => {
  await Promise.all([store.listSecrets(), store.listWebhooks()])
})
const kindOptions: SelectOption[] = SECRET_KINDS.map((k) => ({ title: k, value: k }))

// The value is write-only: sent once, never displayed, cleared from the form after saving.
const secretForm = useZodForm(secretSchema, {
  onSubmit: async (v) => {
    if (selected.value) {
      if (Object.keys(v.value).length) await store.rotateSecret(selected.value.id, v.value)
      else await store.updateSecret(selected.value.id, { name: v.name, kind: v.kind, value: v.value })
    } else await store.createSecret({ name: v.name, kind: v.kind, value: v.value })
  },
  onSuccess: () => {
    drawer.value = false
    secretForm.reset({ name: '', kind: 'dns_credential', value: '' })
    void store.listSecrets()
  },
})
function open(s: Secret | null): void {
  selected.value = s
  error.value = ''
  secretForm.reset({ name: s?.name ?? '', kind: s?.kind ?? 'dns_credential', value: '' })
  drawer.value = true
}
async function remove(): Promise<void> {
  if (!selected.value || !(await confirm.ask({ title: `Delete ${selected.value.name}?`, text: 'Issuers referencing it stop working.', danger: true, confirmLabel: 'Delete' }))) return
  try {
    await store.removeSecret(selected.value.id)
    drawer.value = false
    void store.listSecrets()
  } catch (e) {
    error.value = describe(e)
  }
}
const webhookForm = useZodForm(webhookSchema, {
  initial: { name: '', url: '', event_types: '', secret: '' },
  onSubmit: (v) => store.createWebhook({ name: v.name, url: v.url, event_types: v.event_types, ...(v.secret ? { secret: v.secret } : {}) }),
  onSuccess: () => webhookForm.reset({ name: '', url: '', event_types: '', secret: '' }),
})
async function removeWebhook(w: Webhook): Promise<void> {
  if (!(await confirm.ask({ title: `Remove webhook ${w.name}?`, danger: true, confirmLabel: 'Remove' }))) return
  error.value = ''
  try {
    await store.removeWebhook(w.id)
  } catch (e) {
    error.value = describe(e)
  }
}
const secretColumns: Column<Secret>[] = [
  { key: 'name', label: 'Name', sortable: true },
  { key: 'kind', label: 'Kind', width: 'sm' },
  { key: 'in_use', label: 'In use', width: 'sm', format: (s) => (s.in_use ? 'yes' : '') },
]
const webhookColumns: Column<Webhook>[] = [
  { key: 'name', label: 'Name' },
  { key: 'url', label: 'URL' },
  { key: 'event_types', label: 'Events', format: (w) => w.event_types.join(', '), hideOnStack: true },
]
</script>

<template>
  <UiPage title="Secrets">
    <template #actions><UiButton icon="mdi-plus" data-test="secret-new" @click="open(null)">New secret</UiButton></template>
    <UiAlert v-if="store.error || error" kind="error" class="mb-3">{{ store.error || error }}</UiAlert>
    <UiCard title="Tenant secrets" subtitle="Values are write-only and never returned." :padded="false" class="mb-4" data-test="secrets-card">
      <UiDataTable :items="store.secrets" :columns="secretColumns" caption="Tenant secrets" empty-title="No secrets" :row-attrs="(s) => ({ 'data-test': 'secret-row-' + s.id })" data-test="secrets-table">
        <template #cell-kind="{ row }"><UiBadge>{{ row.kind }}</UiBadge></template>
        <template #cell-in_use="{ row }"><UiIcon v-if="row.in_use" name="mdi-link-variant" size="sm" label="In use" /></template>
        <template #actions="{ row }"><UiButton size="xs" variant="text" :data-test="'secret-rotate-' + row.id" @click="open(row)">Rotate</UiButton></template>
      </UiDataTable>
    </UiCard>
    <UiCard title="Webhooks" subtitle="The signing secret is never shown after creation." data-test="webhooks-card">
      <UiForm :form="webhookForm" class="mb-3">
        <div class="grid grid-cols-1 gap-2 md:grid-cols-12 md:items-end">
          <div class="md:col-span-3"><UiInput v-bind="webhookForm.field('name')" label="Name" size="sm" required data-test="webhook-name" /></div>
          <div class="md:col-span-4"><UiInput v-bind="webhookForm.field('url')" label="URL" type="url" size="sm" required data-test="webhook-url" /></div>
          <div class="md:col-span-3"><UiInput v-bind="webhookForm.field('event_types')" label="Events (comma-separated)" size="sm" required data-test="webhook-events" /></div>
          <div class="md:col-span-2"><UiButton type="submit" block size="sm" :loading="webhookForm.submitting.value" data-test="webhook-add">Add</UiButton></div>
          <div class="md:col-span-6"><UiSecretField v-bind="webhookForm.field('secret')" label="Signing secret (optional, write-only)" data-test="webhook-secret" /></div>
        </div>
      </UiForm>
      <UiDataTable :items="store.webhooks" :columns="webhookColumns" caption="Webhooks" empty-title="No webhooks" :row-attrs="(w) => ({ 'data-test': 'webhook-row-' + w.id })" data-test="webhooks-table">
        <template #actions="{ row }"><UiButton size="xs" variant="text" color="error" icon="mdi-close" icon-only label="Remove webhook" :data-test="'webhook-remove-' + row.id" @click="removeWebhook(row)" /></template>
      </UiDataTable>
    </UiCard>
    <UiDrawer v-model="drawer" :title="selected ? 'Rotate secret' : 'New secret'" size="md" data-test="secret-drawer">
      <UiForm :form="secretForm">
        <div class="flex flex-col gap-3">
          <UiInput v-bind="secretForm.field('name')" label="Name" :disabled="!!selected" required data-test="secret-name" />
          <UiSelect v-bind="secretForm.field('kind')" label="Kind" :options="kindOptions" :clearable="false" :disabled="!!selected" required data-test="secret-kind" />
          <UiTextarea v-bind="secretForm.field('value')" :label="selected ? 'New value (JSON, write-only)' : 'Value (JSON, write-only)'" :rows="4" hint="Never displayed after saving." data-test="secret-value" />
        </div>
      </UiForm>
      <template #actions>
        <UiButton v-if="selected" variant="text" color="error" data-test="secret-delete" @click="remove">Delete</UiButton>
        <UiButton variant="text" @click="drawer = false">Cancel</UiButton>
        <UiButton :loading="secretForm.submitting.value" data-test="secret-save" @click="secretForm.submit()">Save</UiButton>
      </template>
    </UiDrawer>
  </UiPage>
</template>
