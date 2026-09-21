<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { useSecrets } from '@/stores/secrets'
import { describe } from '@/api/client'
import type { Secret, SecretInput, SecretKind } from '@/api/types'

const model = defineModel<boolean>({ required: true })
const props = defineProps<{ secret: Secret | null }>()
const emit = defineEmits<{ saved: [Secret] }>()
const store = useSecrets()

const kinds: SecretKind[] = ['acme_account', 'dns_credential']
const form = reactive({ name: '', kind: 'dns_credential' as SecretKind, value: '' })
const editing = computed(() => !!props.secret)
const err = ref('')
const busy = ref(false)

watch(
  () => [model.value, props.secret] as const,
  ([open]) => {
    if (!open) return
    err.value = ''
    form.name = props.secret?.name ?? ''
    form.kind = props.secret?.kind ?? 'dns_credential'
    form.value = ''
  },
)

function parseValue(): Record<string, unknown> {
  const t = form.value.trim()
  if (!t) return {}
  try {
    const v = JSON.parse(t)
    return typeof v === 'object' && v !== null ? (v as Record<string, unknown>) : { value: t }
  } catch {
    return { value: t }
  }
}

async function save(): Promise<void> {
  busy.value = true
  err.value = ''
  try {
    const value = parseValue()
    let saved: Secret
    if (props.secret) {
      // Rotating replaces the write-only value; empty means metadata only.
      saved = Object.keys(value).length ? await store.rotateSecret(props.secret.id, value) : await store.updateSecret(props.secret.id, { name: form.name, kind: form.kind, value })
    } else {
      const input: SecretInput = { name: form.name, kind: form.kind, value }
      saved = await store.createSecret(input)
    }
    emit('saved', saved)
    model.value = false
  } catch (e) {
    err.value = describe(e)
  } finally {
    busy.value = false
  }
}

async function remove(): Promise<void> {
  if (!props.secret) return
  busy.value = true
  err.value = ''
  try {
    await store.removeSecret(props.secret.id)
    model.value = false
  } catch (e) {
    err.value = describe(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <v-navigation-drawer v-model="model" location="right" temporary width="460" data-test="secret-drawer">
    <v-card flat>
      <v-card-title>{{ editing ? 'Rotate secret' : 'New secret' }}</v-card-title>
      <v-card-text>
        <v-text-field v-model="form.name" label="Name" density="compact" :disabled="editing" data-test="secret-name" />
        <v-select v-model="form.kind" :items="kinds" label="Kind" density="compact" :disabled="editing" data-test="secret-kind" />
        <v-textarea
          v-model="form.value"
          :label="editing ? 'New value (JSON, write-only)' : 'Value (JSON, write-only)'"
          rows="4"
          density="compact"
          hint="Never displayed after saving."
          persistent-hint
          data-test="secret-value"
        />
        <v-alert v-if="err" type="error" variant="tonal" density="compact" class="mt-2" data-test="secret-error">{{ err }}</v-alert>
      </v-card-text>
      <v-card-actions>
        <v-btn v-if="editing" color="error" variant="text" data-test="secret-delete" @click="remove">Delete</v-btn>
        <v-spacer />
        <v-btn @click="model = false">Cancel</v-btn>
        <v-btn color="primary" :loading="busy" data-test="secret-save" @click="save">Save</v-btn>
      </v-card-actions>
    </v-card>
  </v-navigation-drawer>
</template>
