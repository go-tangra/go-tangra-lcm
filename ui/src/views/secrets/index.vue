<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { useSecrets } from '@/stores/secrets'
import { describe } from '@/api/client'
import SecretDrawer from '@/components/SecretDrawer.vue'
import type { Secret } from '@/api/types'

const store = useSecrets()
const drawer = ref(false)
const selected = ref<Secret | null>(null)
const err = ref('')
const webhookForm = reactive({ name: '', url: '', event_types: '', secret: '' })

onMounted(async () => {
  await Promise.all([store.listSecrets(), store.listWebhooks()])
})

function open(s: Secret | null): void {
  selected.value = s
  drawer.value = true
}

async function addWebhook(): Promise<void> {
  err.value = ''
  try {
    await store.createWebhook({
      name: webhookForm.name,
      url: webhookForm.url,
      event_types: webhookForm.event_types.split(',').map((s) => s.trim()).filter(Boolean),
      ...(webhookForm.secret ? { secret: webhookForm.secret } : {}),
    })
    webhookForm.name = ''
    webhookForm.url = ''
    webhookForm.event_types = ''
    webhookForm.secret = ''
  } catch (e) {
    err.value = describe(e)
  }
}

async function removeWebhook(id: string): Promise<void> {
  err.value = ''
  try {
    await store.removeWebhook(id)
  } catch (e) {
    err.value = describe(e)
  }
}
</script>

<template>
  <div>
    <div class="d-flex align-center mb-4">
      <h1 class="text-h5">Secrets</h1>
      <v-spacer />
      <v-btn color="primary" prepend-icon="mdi-plus" data-test="secret-new" @click="open(null)">New secret</v-btn>
    </div>
    <v-alert v-if="store.error || err" type="error" variant="tonal" density="compact" class="mb-3">{{ store.error || err }}</v-alert>
    <v-card title="Tenant secrets" data-test="secrets-card">
      <v-table data-test="secrets-table">
        <thead>
          <tr><th>Name</th><th>Kind</th><th>In use</th><th class="text-right">Actions</th></tr>
        </thead>
        <tbody>
          <tr v-for="s in store.secrets" :key="s.id" :data-test="'secret-row-' + s.id">
            <td>{{ s.name }}</td>
            <td><v-chip size="x-small" variant="tonal">{{ s.kind }}</v-chip></td>
            <td><v-icon v-if="s.in_use" icon="mdi-link-variant" size="small" /></td>
            <td class="text-right"><v-btn size="x-small" variant="text" :data-test="'secret-rotate-' + s.id" @click="open(s)">Rotate</v-btn></td>
          </tr>
          <tr v-if="!store.secrets.length"><td colspan="4" class="text-medium-emphasis">No secrets. Values are write-only and never returned.</td></tr>
        </tbody>
      </v-table>
    </v-card>

    <v-card class="mt-4" title="Webhooks" data-test="webhooks-card">
      <v-card-text>
        <v-row dense>
          <v-col cols="12" md="3"><v-text-field v-model="webhookForm.name" label="Name" density="compact" data-test="webhook-name" /></v-col>
          <v-col cols="12" md="4"><v-text-field v-model="webhookForm.url" label="URL" density="compact" data-test="webhook-url" /></v-col>
          <v-col cols="12" md="3"><v-text-field v-model="webhookForm.event_types" label="Events (comma-separated)" density="compact" data-test="webhook-events" /></v-col>
          <v-col cols="12" md="2" class="d-flex align-center"><v-btn color="primary" size="small" data-test="webhook-add" @click="addWebhook">Add</v-btn></v-col>
        </v-row>
        <v-table data-test="webhooks-table">
          <thead>
            <tr><th>Name</th><th>URL</th><th>Events</th><th class="text-right">Actions</th></tr>
          </thead>
          <tbody>
            <tr v-for="w in store.webhooks" :key="w.id" :data-test="'webhook-row-' + w.id">
              <td>{{ w.name }}</td>
              <td class="text-truncate" style="max-width: 260px">{{ w.url }}</td>
              <td>{{ w.event_types.join(', ') }}</td>
              <td class="text-right"><v-btn icon="mdi-close" size="x-small" variant="text" :data-test="'webhook-remove-' + w.id" @click="removeWebhook(w.id)" /></td>
            </tr>
            <tr v-if="!store.webhooks.length"><td colspan="4" class="text-medium-emphasis">No webhooks. The signing secret is never shown after creation.</td></tr>
          </tbody>
        </v-table>
      </v-card-text>
    </v-card>

    <SecretDrawer v-model="drawer" :secret="selected" @saved="store.listSecrets()" />
  </div>
</template>
