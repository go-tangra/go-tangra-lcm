import { defineStore } from 'pinia'
import { api } from '@/api/client'
import type { Secret, SecretInput, Webhook, WebhookInput } from '@/api/types'
import { pagedList, SECRET_LIST, WEBHOOK_LIST } from '@/stores/paged'

/** The tenant-secrets table: one server page (metadata only). */
export const useSecretList = defineStore('lcm-secret-list', () => pagedList<Secret>('secrets', SECRET_LIST.first))

/** The webhooks table: one server page. */
export const useWebhookList = defineStore('lcm-webhook-list', () => pagedList<Webhook>('webhooks', WEBHOOK_LIST.first))

// Tenant secrets (ACME account / DNS credentials, values write-only) and the
// outbound webhook endpoints. Both surfaces sit behind secrets:manage /
// webhooks:manage. The view reloads the page after a change.
export const useSecrets = defineStore('lcm-secrets', () => {
  async function createSecret(input: SecretInput): Promise<Secret> {
    return api<Secret>('POST', 'secrets', input)
  }

  async function updateSecret(id: string, input: SecretInput): Promise<Secret> {
    return api<Secret>('PUT', 'secrets/' + id, input)
  }

  async function rotateSecret(id: string, value: Record<string, unknown>): Promise<Secret> {
    return api<Secret>('POST', 'secrets/' + id + '/rotate', { value })
  }

  async function removeSecret(id: string): Promise<void> {
    await api('POST', 'secrets/' + id + '/remove')
  }

  async function createWebhook(input: WebhookInput): Promise<Webhook> {
    return api<Webhook>('POST', 'webhooks', input)
  }

  async function removeWebhook(id: string): Promise<void> {
    await api('POST', 'webhooks/' + id + '/remove')
  }

  return { createSecret, updateSecret, rotateSecret, removeSecret, createWebhook, removeWebhook }
})
