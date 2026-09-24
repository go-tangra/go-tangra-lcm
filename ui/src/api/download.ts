import { api, ApiError } from './client'

/** Hands arbitrary text to the browser as a downloaded file. */
export function saveText(text: string, filename: string, mime = 'application/octet-stream'): number {
  const url = URL.createObjectURL(new Blob([text], { type: mime }))
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
  return text.length
}

/** POSTs to an export route and hands the JSON body to the browser as a file. */
export async function downloadJSON(path: string, filename: string): Promise<number> {
  const body = await api<unknown>('POST', path)
  const blob = new Blob([JSON.stringify(body, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
  return blob.size
}

/** Reads a picked file as text, refusing anything above the limit. */
export function readFile(file: File, limit = 16 * 1024 * 1024): Promise<string> {
  if (file.size > limit) return Promise.reject(new ApiError(413, 'body_too_large'))
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => resolve(String(reader.result ?? ''))
    reader.onerror = () => reject(new ApiError(0, 'unreadable'))
    reader.readAsText(file)
  })
}
