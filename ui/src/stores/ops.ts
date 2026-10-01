import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api, ApiError, BASE } from '@/api/client'
import { downloadJSON, readFile } from '@/api/download'
import type { AuditFilter, AuditItem, BackupReport, Stats } from '@/api/types'
import { AUDIT_LIST, pagedList } from '@/stores/paged'

/**
 * The audit table: one server page, newest first. Without from/to the server
 * covers the last 7 days (the total is exact within that window).
 */
export const useAuditList = defineStore('lcm-audit-list', () => pagedList<AuditItem, AuditFilter>('audit', AUDIT_LIST.first))

export const useOps = defineStore('lcm-ops', () => {
  const stats = ref<Stats | null>(null)
  const loading = ref(false)
  const error = ref('')

  async function loadStats(): Promise<void> {
    try {
      stats.value = await api<Stats>('GET', 'stats')
    } catch (e) {
      error.value = (e as Error).message
    }
  }

  async function exportBackup(includeCredentials: boolean): Promise<number> {
    if (includeCredentials) {
      const doc = await api<unknown>('POST', 'backup/export', { include_credentials: true })
      const blob = JSON.stringify(doc, null, 2)
      const url = URL.createObjectURL(new Blob([blob], { type: 'application/json' }))
      const a = document.createElement('a')
      a.href = url
      a.download = 'lcm-backup.json'
      document.body.appendChild(a)
      a.click()
      a.remove()
      setTimeout(() => URL.revokeObjectURL(url), 1000)
      return blob.length
    }
    return downloadJSON(BASE + '/backup/export', 'lcm-backup.json')
  }

  async function importBackup(file: File, mode: 'skip' | 'overwrite'): Promise<BackupReport> {
    const text = await readFile(file)
    let doc: unknown
    try {
      doc = JSON.parse(text)
    } catch {
      throw new ApiError(422, 'validation_failed')
    }
    return api<BackupReport>('POST', 'backup/import', doc, { query: { mode } })
  }

  return { stats, loading, error, loadStats, exportBackup, importBackup }
})
