import { defineStore } from 'pinia'
import { ref } from 'vue'
import { useCertificates } from '@/stores/certificates'

// A single shared EventSource per signed-in person relays the module's live
// events through the gateway (GET /gateway/v1/stream (shared platform bus)).
// certificate.issued / .renewed / .revoked reload the certificates page on
// screen (one debounced reload per burst: a server page keeps its sort and
// boundaries, a client-side insert would not); every event is also handed to registered listeners (the header widget
// and views use them). The stream is reference-counted so several views share
// one connection.
export type Listener = (type: string, data: unknown) => void

const CERT_EVENTS = ['certificate.issued', 'certificate.renewed', 'certificate.revoked']
const OTHER_EVENTS = ['certificate.failed', 'request.created', 'request.decided', 'job.completed', 'job.failed', 'reset']

/** The wait before a burst of certificate events reloads the page (research D9). */
export const RELOAD_DELAY = 300

/**
 * Coalesces bursts of live events into one call after wait ms (a server page
 * reload per burst, not per event); cancel() drops a pending call.
 */
export function coalesce(fn: () => void, wait = RELOAD_DELAY): { trigger: () => void; cancel: () => void } {
  let timer: ReturnType<typeof setTimeout> | null = null
  return {
    trigger: () => {
      if (timer) return
      timer = setTimeout(() => {
        timer = null
        fn()
      }, wait)
    },
    cancel: () => {
      if (timer) clearTimeout(timer)
      timer = null
    },
  }
}

export const useLive = defineStore('lcm-live', () => {
  const connected = ref(false)
  const reloadCertificates = coalesce(() => void useCertificates().reload())
  let source: EventSource | null = null
  let refs = 0
  const listeners = new Set<Listener>()

  function handle(type: string, raw: string): void {
    let data: unknown = {}
    try {
      data = JSON.parse(raw)
    } catch {
      /* non-JSON payloads are ignored */
    }
    if (CERT_EVENTS.includes(type)) {
      useCertificates().applyEvent(type, data)
      reloadCertificates.trigger()
    }
    for (const l of listeners) l(type, data)
  }

  function open(): void {
    if (source) return
    source = new EventSource('/gateway/v1/stream', { withCredentials: true })
    source.onopen = () => (connected.value = true)
    source.onerror = () => (connected.value = false)
    for (const t of [...CERT_EVENTS, ...OTHER_EVENTS]) source.addEventListener(t, (e) => handle(t, (e as MessageEvent).data))
    source.addEventListener('message', (e) => handle((e as MessageEvent).type, (e as MessageEvent).data))
  }

  /** Opens the stream (first caller) and returns a release function. */
  function connect(): () => void {
    refs += 1
    open()
    return () => {
      refs -= 1
      if (refs <= 0) close()
    }
  }

  function close(): void {
    reloadCertificates.cancel()
    refs = 0
    source?.close()
    source = null
    connected.value = false
  }

  function on(l: Listener): () => void {
    listeners.add(l)
    return () => listeners.delete(l)
  }

  // Exposed for tests: inject a fake event.
  function _emit(type: string, raw: string): void {
    handle(type, raw)
  }

  return { connected, connect, close, on, _emit }
})
