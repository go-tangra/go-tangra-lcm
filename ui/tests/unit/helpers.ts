import { vi } from 'vitest'
import { type Plugin } from 'vue'
import { createRouter, createMemoryHistory } from 'vue-router'
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
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/:pathMatch(.*)*', component: { template: '<div/>' } }] })
  return [router, [abilitiesPlugin as Plugin, createMongoAbility(rules), { useGlobalProperties: true }]]
}

export const perms = { read: true, write: true, delete: true, share: true, use: true }
