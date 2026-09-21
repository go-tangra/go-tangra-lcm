import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api } from '@/api/client'
import type { Secret, SecretInput, Webhook, WebhookInput } from '@/api/types'

// Tenant secrets (ACME account / DNS credentials, values write-only) and the
// outbound webhook endpoints. Both surfaces sit behind secrets:manage /
// webhooks:manage.
export const useSecrets = defineStore('lcm-secrets', () => {
  const secrets = ref<Secret[]>([])
  const webhooks = ref<Webhook[]>([])
  const loading = ref(false)
  const error = ref('')

  async function listSecrets(): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      const out = await api<{ items: Secret[] }>('GET', 'secrets')
      secrets.value = out.items
    } catch (e) {
      error.value = (e as Error).message
    } finally {
      loading.value = false
    }
  }

  async function createSecret(input: SecretInput): Promise<Secret> {
    const s = await api<Secret>('POST', 'secrets', input)
    secrets.value = [s, ...secrets.value]
    return s
  }

  async function updateSecret(id: string, input: SecretInput): Promise<Secret> {
    const s = await api<Secret>('PUT', 'secrets/' + id, input)
    secrets.value = secrets.value.map((x) => (x.id === id ? s : x))
    return s
  }

  async function rotateSecret(id: string, value: Record<string, unknown>): Promise<Secret> {
    const s = await api<Secret>('POST', 'secrets/' + id + '/rotate', { value })
    secrets.value = secrets.value.map((x) => (x.id === id ? { ...x, ...s } : x))
    return s
  }

  async function removeSecret(id: string): Promise<void> {
    await api('POST', 'secrets/' + id + '/remove')
    secrets.value = secrets.value.filter((x) => x.id !== id)
  }

  async function listWebhooks(): Promise<void> {
    try {
      const out = await api<{ items: Webhook[] }>('GET', 'webhooks')
      webhooks.value = out.items
    } catch (e) {
      error.value = (e as Error).message
    }
  }

  async function createWebhook(input: WebhookInput): Promise<Webhook> {
    const w = await api<Webhook>('POST', 'webhooks', input)
    webhooks.value = [w, ...webhooks.value]
    return w
  }

  async function removeWebhook(id: string): Promise<void> {
    await api('POST', 'webhooks/' + id + '/remove')
    webhooks.value = webhooks.value.filter((x) => x.id !== id)
  }

  return { secrets, webhooks, loading, error, listSecrets, createSecret, updateSecret, rotateSecret, removeSecret, listWebhooks, createWebhook, removeWebhook }
})
