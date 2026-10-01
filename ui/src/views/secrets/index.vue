<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import { UiPage, UiAlert, UiCard, UiButton, UiDataTable, UiBadge, UiIcon, UiDrawer, UiForm, UiInput, UiSelect, UiTextarea, UiSecretField, useConfirm, useListQuery, type Column, type SelectOption } from '@go-tangra/ui'
import { useZodForm } from '@go-tangra/ui/forms'
import { useSecretList, useSecrets, useWebhookList } from '@/stores/secrets'
import { SECRET_LIST, WEBHOOK_LIST } from '@/stores/paged'
import { describe } from '@/api/client'
import { secretSchema, webhookSchema, SECRET_KINDS } from '@/schemas'
import type { Secret, Webhook } from '@/api/types'

const store = useSecrets()
const confirm = useConfirm()
const drawer = ref(false)
const selected = ref<Secret | null>(null)
const error = ref('')
const secrets = useSecretList()
const webhooks = useWebhookList()

// --- server paging and sorting, one query per table (?secrets.page=…, ?webhooks.page=…) ---
const sq = useListQuery('secrets', SECRET_LIST.opts)
const wq = useListQuery('webhooks', WEBHOOK_LIST.opts)
async function loadSecrets(): Promise<void> {
  const res = await secrets.list({}, sq.query.value)
  if (res?.page) sq.clampTo(res.page)
}
async function loadWebhooks(): Promise<void> {
  const res = await webhooks.list({}, wq.query.value)
  if (res?.page) wq.clampTo(res.page)
}
watch(sq.query, () => void loadSecrets())
watch(wq.query, () => void loadWebhooks())
onMounted(async () => {
  await Promise.all([loadSecrets(), loadWebhooks()])
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
    void loadSecrets()
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
    void loadSecrets()
  } catch (e) {
    error.value = describe(e)
  }
}
const webhookForm = useZodForm(webhookSchema, {
  initial: { name: '', url: '', event_types: '', secret: '' },
  onSubmit: (v) => store.createWebhook({ name: v.name, url: v.url, event_types: v.event_types, ...(v.secret ? { secret: v.secret } : {}) }),
  onSuccess: () => {
    webhookForm.reset({ name: '', url: '', event_types: '', secret: '' })
    void loadWebhooks()
  },
})
async function removeWebhook(w: Webhook): Promise<void> {
  if (!(await confirm.ask({ title: `Remove webhook ${w.name}?`, danger: true, confirmLabel: 'Remove' }))) return
  error.value = ''
  try {
    await store.removeWebhook(w.id)
    await loadWebhooks()
  } catch (e) {
    error.value = describe(e)
  }
}
const secretColumns: Column<Secret>[] = [
  { key: 'name', label: 'Name', sortable: true },
  { key: 'kind', label: 'Kind', width: 'sm', sortable: true },
  { key: 'in_use', label: 'In use', width: 'sm', format: (s) => (s.in_use ? 'yes' : '') },
]
const webhookColumns: Column<Webhook>[] = [
  { key: 'name', label: 'Name', sortable: true },
  { key: 'url', label: 'URL' },
  { key: 'event_types', label: 'Events', format: (w) => w.event_types.join(', '), hideOnStack: true },
]
</script>

<template>
  <UiPage title="Secrets">
    <template #actions><UiButton icon="mdi-plus" data-test="secret-new" @click="open(null)">New secret</UiButton></template>
    <UiAlert v-if="secrets.error || webhooks.error || error" kind="error" class="mb-3">{{ secrets.error || webhooks.error || error }}</UiAlert>
    <UiCard title="Tenant secrets" subtitle="Values are write-only and never returned." :padded="false" class="mb-4" data-test="secrets-card">
      <UiDataTable :items="secrets.items" :columns="secretColumns" :loading="secrets.loading" :total="secrets.total" :page="sq.page.value" :page-size="sq.pageSize.value" :sort="sq.sort.value" caption="Tenant secrets" empty-title="No secrets" :row-attrs="(s) => ({ 'data-test': 'secret-row-' + s.id })" data-test="secrets-table" @update:page="sq.setPage" @update:page-size="sq.setPageSize" @update:sort="sq.setSort">
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
      <UiDataTable :items="webhooks.items" :columns="webhookColumns" :loading="webhooks.loading" :total="webhooks.total" :page="wq.page.value" :page-size="wq.pageSize.value" :sort="wq.sort.value" caption="Webhooks" empty-title="No webhooks" :row-attrs="(w) => ({ 'data-test': 'webhook-row-' + w.id })" data-test="webhooks-table" @update:page="wq.setPage" @update:page-size="wq.setPageSize" @update:sort="wq.setSort">
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
