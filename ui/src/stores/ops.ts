import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api, ApiError, BASE } from '@/api/client'
import { downloadJSON, readFile } from '@/api/download'
import type { AuditFilter, AuditItem, BackupReport, Stats } from '@/api/types'

export const useOps = defineStore('lcm-ops', () => {
  const stats = ref<Stats | null>(null)
  const audit = ref<AuditItem[]>([])
  const auditNext = ref<string | undefined>()
  const loading = ref(false)
  const error = ref('')

  async function loadStats(): Promise<void> {
    try {
      stats.value = await api<Stats>('GET', 'stats')
    } catch (e) {
      error.value = (e as Error).message
    }
  }

  async function loadAudit(filter: AuditFilter = {}, cursor?: string): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      const page = await api<{ items: AuditItem[]; next_cursor?: string }>('GET', 'audit', undefined, { query: { ...filter, cursor } })
      audit.value = cursor ? [...audit.value, ...page.items] : page.items
      auditNext.value = page.next_cursor
    } catch (e) {
      error.value = (e as Error).message
    } finally {
      loading.value = false
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

  return { stats, audit, auditNext, loading, error, loadStats, loadAudit, exportBackup, importBackup }
})
