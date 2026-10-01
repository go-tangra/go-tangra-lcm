// Pure presentation helpers for the certificate drawer's "Certificate"
// section (CertificateDetails.vue). Every input is a value decoded
// server-side from the certificate bytes; nothing here re-derives X.509.
import type { CertificateDetails } from '@/api/types'

const DAY = 86_400_000

/** Days at or below which a valid certificate counts as "expiring soon". */
export const EXPIRING_SOON_DAYS = 30

export type BadgeColor = 'success' | 'warning' | 'error' | 'info'
export interface ValidityState { key: 'valid' | 'expiring' | 'expired' | 'not_yet_valid'; label: string; color: BadgeColor; hint: string; icon: string }

const days = (n: number) => (n === 1 ? '1 day' : n + ' days')

/** The summary badge for the leaf, from the server-computed validity. */
export function validityState(v: CertificateDetails['validity'], now: number): ValidityState {
  const n = Math.abs(v.days_remaining)
  if (v.status === 'expired') return { key: 'expired', label: 'Expired', color: 'error', hint: n === 0 ? 'expired today' : 'expired ' + days(n) + ' ago', icon: 'mdi-alert-circle-outline' }
  if (v.status === 'not_yet_valid') {
    const until = Math.max(0, Math.ceil((Date.parse(v.not_before) - now) / DAY))
    return { key: 'not_yet_valid', label: 'Not yet valid', color: 'info', hint: until <= 0 ? 'starts within a day' : 'starts in ' + days(until), icon: 'mdi-calendar-clock' }
  }
  const hint = v.days_remaining === 0 ? 'expires within a day' : days(v.days_remaining) + ' left'
  if (v.days_remaining <= EXPIRING_SOON_DAYS) return { key: 'expiring', label: 'Expiring soon', color: 'warning', hint, icon: 'mdi-calendar-alert' }
  return { key: 'valid', label: 'Valid', color: 'success', hint, icon: 'mdi-check-decagram' }
}

/** Badge for a chain entry, which only carries not_after. */
export function expiryBadge(notAfter: string, now: number): { label: string; color: BadgeColor } {
  const left = Math.floor((Date.parse(notAfter) - now) / DAY)
  if (left < 0) return { label: 'Expired', color: 'error' }
  if (left <= EXPIRING_SOON_DAYS) return { label: 'Expires in ' + days(left), color: 'warning' }
  return { label: 'Valid', color: 'success' }
}

/** Share of the validity window elapsed at `now`, 0–100 (clamped). */
export function elapsedPercent(notBefore: string, notAfter: string, now: number): number {
  const a = Date.parse(notBefore)
  const b = Date.parse(notAfter)
  if (!(b > a)) return now >= b ? 100 : 0
  return Math.min(100, Math.max(0, ((now - a) / (b - a)) * 100))
}

// Widths in 2 % steps, spelled out so Tailwind emits them (the edge CSP
// forbids inline styles, so the bar cannot be sized with `style`).
const WIDTHS = [
  'w-[0%]', 'w-[2%]', 'w-[4%]', 'w-[6%]', 'w-[8%]', 'w-[10%]', 'w-[12%]', 'w-[14%]', 'w-[16%]', 'w-[18%]', 'w-[20%]', 'w-[22%]', 'w-[24%]', 'w-[26%]', 'w-[28%]', 'w-[30%]', 'w-[32%]', 'w-[34%]', 'w-[36%]', 'w-[38%]', 'w-[40%]', 'w-[42%]', 'w-[44%]', 'w-[46%]', 'w-[48%]',
  'w-[50%]', 'w-[52%]', 'w-[54%]', 'w-[56%]', 'w-[58%]', 'w-[60%]', 'w-[62%]', 'w-[64%]', 'w-[66%]', 'w-[68%]', 'w-[70%]', 'w-[72%]', 'w-[74%]', 'w-[76%]', 'w-[78%]', 'w-[80%]', 'w-[82%]', 'w-[84%]', 'w-[86%]', 'w-[88%]', 'w-[90%]', 'w-[92%]', 'w-[94%]', 'w-[96%]', 'w-[98%]', 'w-[100%]',
] as const

/** The Tailwind width class nearest to a percentage. */
export function widthClass(percent: number): string {
  return WIDTHS[Math.round(Math.min(100, Math.max(0, percent)) / 2)]!
}

/** Whole days between two instants, e.g. a certificate's lifetime. */
export function durationLabel(notBefore: string, notAfter: string): string {
  const n = Math.round((Date.parse(notAfter) - Date.parse(notBefore)) / DAY)
  if (n >= 365) {
    const y = Math.floor(n / 365)
    const r = n - y * 365
    return days(n) + ' (' + (y === 1 ? '1 year' : y + ' years') + (r ? ' ' + days(r) : '') + ')'
  }
  return days(n)
}

/** "ECDSA P-256", "RSA 2048", "Ed25519". */
export function keyLabel(k: CertificateDetails['public_key']): string {
  if (k.curve) return k.algorithm + ' ' + k.curve
  if (k.algorithm === 'Ed25519' || !k.size) return k.algorithm
  return k.algorithm + ' ' + k.size
}

const ATTRS: Record<string, string> = {
  CN: 'Common name',
  O: 'Organization',
  OU: 'Organizational unit',
  L: 'Locality',
  ST: 'State / province',
  C: 'Country',
  STREET: 'Street',
  POSTALCODE: 'Postal code',
  SERIALNUMBER: 'Serial number',
  DC: 'Domain component',
  UID: 'User ID',
  '1.2.840.113549.1.9.1': 'Email',
}

export interface DNPart { type: string; label: string; value: string }

/**
 * Splits an RFC 2253 distinguished name (as Go's pkix.Name.String() prints
 * it: most specific first) into attribute/value pairs, honouring backslash
 * escapes, in the printed order (CN first). Multi-valued RDNs ("+")
 * become separate pairs.
 */
export function parseDN(dn: string): DNPart[] {
  const out: DNPart[] = []
  let cur = ''
  const push = () => {
    const i = cur.indexOf('=')
    if (i > 0) {
      const type = cur.slice(0, i).trim()
      out.push({ type, label: ATTRS[type.toUpperCase()] ?? ATTRS[type] ?? type, value: cur.slice(i + 1) })
    }
    cur = ''
  }
  for (let i = 0; i < dn.length; i++) {
    const c = dn[i]!
    if (c === '\\' && i + 1 < dn.length) {
      const hex = dn.slice(i + 1, i + 3)
      if (/^[0-9a-fA-F]{2}$/.test(hex)) {
        cur += String.fromCharCode(parseInt(hex, 16))
        i += 2
      } else {
        cur += dn[++i]
      }
    } else if (c === ',' || c === '+') push()
    else cur += c
  }
  push()
  return out
}

/** Groups colon-separated hex pairs, keeping the colons so the text copies back verbatim. */
export function hexGroups(hex: string, size = 4): string[] {
  const pairs = hex.split(':')
  const out: string[] = []
  for (let i = 0; i < pairs.length; i += size) {
    const last = i + size >= pairs.length
    out.push(pairs.slice(i, i + size).join(':') + (last ? '' : ':'))
  }
  return out
}

/** "AB:CD:EF:01…" — the first few pairs of a fingerprint. */
export function shortHex(hex: string, pairs = 6): string {
  const p = hex.split(':')
  return p.length > pairs ? p.slice(0, pairs).join(':') + '…' : hex
}

/** Only web URLs become links; ldap: and the like stay plain text. */
export const isWebURL = (u: string) => /^https?:\/\//i.test(u)
