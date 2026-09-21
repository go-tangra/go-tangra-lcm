import { vi } from 'vitest'
import { type Plugin } from 'vue'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import { abilitiesPlugin } from '@casl/vue'
import { createMongoAbility } from '@casl/ability'

export type Reply = { status: number; body: unknown }

/** Stubs fetch with a request handler and records calls. */
export function stubFetch(handler: (url: string, init?: RequestInit) => Reply) {
  const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const { status, body } = handler(String(input), init)
    return new Response(status === 204 ? null : JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
  })
  vi.stubGlobal('fetch', fn)
  return fn
}

export function plugins(rules: Array<{ action: string; subject: string }> = [{ action: 'manage', subject: 'all' }]): Array<Plugin | [Plugin, ...unknown[]]> {
  return [createVuetify({ components, directives }), [abilitiesPlugin as Plugin, createMongoAbility(rules), { useGlobalProperties: true }]]
}

export const perms = { read: true, write: true, delete: true, share: true, use: true }
