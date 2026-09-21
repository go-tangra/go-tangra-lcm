import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api } from '@/api/client'
import type { RoleHit, UserHit } from '@/api/types'

// Names for the ids the lcm API hands back: user ids resolve through the auth
// module's batch lookup (public profiles of the caller's tenant; unknown or
// foreign ids come back absent and stay as ids), role slugs through the role
// list. Both are cached for the session. This is the same auth-service surface
// the notification remote uses.
export const useDirectory = defineStore('lcm-directory', () => {
  const users = ref<Record<string, UserHit | null>>({})
  const roles = ref<Record<string, RoleHit>>({})
  let rolesLoaded: Promise<void> | null = null
  const pending = new Map<string, Promise<void>>()

  async function resolveUsers(ids: Array<string | undefined | null>): Promise<void> {
    const want = [...new Set(ids.filter((id): id is string => !!id && !(id in users.value) && !pending.has(id)))]
    const waits: Promise<void>[] = ids.filter((id): id is string => !!id && pending.has(id)).map((id) => pending.get(id)!)
    for (let i = 0; i < want.length; i += 100) {
      const chunk = want.slice(i, i + 100)
      const p = api<{ items: UserHit[] }>('POST', '/api/v1/users/lookup', { ids: chunk })
        .then((out) => {
          const found = new Map(out.items.map((u) => [u.id, u]))
          for (const id of chunk) users.value[id] = found.get(id) ?? null
        })
        .catch(() => {
          /* leave them unknown so a later call retries */
        })
        .finally(() => chunk.forEach((id) => pending.delete(id)))
      chunk.forEach((id) => pending.set(id, p))
      waits.push(p)
    }
    await Promise.all(waits)
  }

  async function loadRoles(): Promise<void> {
    rolesLoaded ??= api<RoleHit[]>('GET', '/api/v1/roles')
      .then((list) => {
        for (const r of list) roles.value[r.slug] = r
      })
      .catch(() => {
        rolesLoaded = null
      })
    await rolesLoaded
  }

  function userName(id: string | undefined | null): string {
    if (!id) return ''
    if (id.startsWith('spiffe://')) return id.replace('spiffe://example.org/svc/', '') + ' (service)'
    return users.value[id]?.display_name ?? id
  }

  function roleName(slug: string | undefined | null): string {
    if (!slug) return ''
    return roles.value[slug]?.display_name ?? slug
  }

  async function searchUsers(q: string): Promise<UserHit[]> {
    // The auth module's public-profile search (GET /api/v1/users?q=…) requires
    // at least two characters.
    if (q.trim().length < 2) return []
    try {
      const out = await api<{ items: UserHit[] }>('GET', '/api/v1/users', undefined, { query: { q: q.trim() } })
      for (const u of out.items) users.value[u.id] = u
      return out.items
    } catch {
      return []
    }
  }

  return { users, roles, resolveUsers, loadRoles, userName, roleName, searchUsers }
})
