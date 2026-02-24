/**
 * 深度克隆一个值，支持对象、数组、Map、Set、Date、RegExp 等类型，且能处理循环引用。
 * @param value
 */
export function deepClone<T>(value: T): T {
  // 尝试使用原生 structuredClone，但发生异常时回退到手写实现
  if (typeof (globalThis as any).structuredClone === 'function') {
    try {
      return (globalThis as any).structuredClone(value);
    } catch {
      // structuredClone 不能克隆某些类型（如 Vue 响应式代理、DOM 节点、window 等）
      // 回退到手写深拷贝
    }
  }

  const seen = new WeakMap<any, any>();

  const _clone = (v: any): any => {
    if (v === null || typeof v !== 'object') return v;
    if (v instanceof Date) return new Date(v.getTime());
    if (v instanceof RegExp) return new RegExp(v.source, v.flags);
    if (v instanceof Map) {
      if (seen.has(v)) return seen.get(v);
      const m = new Map();
      seen.set(v, m);
      for (const [k, val] of v) m.set(_clone(k), _clone(val));
      return m;
    }
    if (v instanceof Set) {
      if (seen.has(v)) return seen.get(v);
      const s = new Set();
      seen.set(v, s);
      for (const item of v) s.add(_clone(item));
      return s;
    }
    if (seen.has(v)) return seen.get(v);

    if (Array.isArray(v)) {
      const arr: any[] = [];
      seen.set(v, arr);
      for (let i = 0; i < v.length; i++) arr[i] = _clone(v[i]);
      return arr;
    }

    const obj: any = Object.create(Object.getPrototypeOf(v));
    seen.set(v, obj);
    for (const key of Reflect.ownKeys(v)) {
      obj[key as any] = _clone((v as any)[key as any]);
    }
    return obj;
  };

  return _clone(value);
}

/**
 * Download content as a file
 * @param content - The content to download
 * @param filename - The filename for the download
 * @param mimeType - The MIME type of the content
 */
export function downloadFile(
  content: string | Blob,
  filename: string,
  mimeType: string = 'application/octet-stream',
): void {
  const blob =
    content instanceof Blob ? content : new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);

  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);

  URL.revokeObjectURL(url);
}

/**
 * Generate a CSR (Certificate Signing Request) in the browser using Web Crypto API
 * Note: This is a simplified implementation. For production use, consider using a
 * dedicated library like node-forge or pkijs.
 */
export interface CsrOptions {
  commonName: string;
  dnsNames?: string[];
  ipAddresses?: string[];
  keyType?: 'RSA' | 'ECDSA';
  keySize?: number;
}

export interface CsrResult {
  csrPem: string;
  privateKeyPem: string;
}

export async function generateCsr(options: CsrOptions): Promise<CsrResult> {
  const { commonName, dnsNames = [], keySize = 2048 } = options;

  // Generate RSA key pair
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: keySize,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  );

  // Export private key
  const privateKeyDer = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
  const privateKeyPem = derToPem(privateKeyDer, 'PRIVATE KEY');

  // Export public key
  const publicKeyDer = await crypto.subtle.exportKey('spki', keyPair.publicKey);

  // Build CSR
  const csrDer = buildCsr(commonName, dnsNames, publicKeyDer, keyPair.privateKey);
  const csrPem = derToPem(await csrDer, 'CERTIFICATE REQUEST');

  return { csrPem, privateKeyPem };
}

function derToPem(der: ArrayBuffer, label: string): string {
  const base64 = btoa(String.fromCharCode(...new Uint8Array(der)));
  const lines = base64.match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----`;
}

async function buildCsr(
  commonName: string,
  dnsNames: string[],
  publicKeyDer: ArrayBuffer,
  privateKey: CryptoKey,
): Promise<ArrayBuffer> {
  // Simplified CSR structure - for production use a proper ASN.1 library
  const subject = encodeDistinguishedName(commonName);
  const publicKeyInfo = new Uint8Array(publicKeyDer);

  // Build CSR info (to be signed)
  const csrInfo = encodeCsrInfo(subject, publicKeyInfo, dnsNames);

  // Sign the CSR info
  const signature = await crypto.subtle.sign(
    { name: 'RSASSA-PKCS1-v1_5' },
    privateKey,
    csrInfo,
  );

  // Build final CSR
  return encodeCsr(csrInfo, new Uint8Array(signature));
}

function encodeDistinguishedName(commonName: string): Uint8Array {
  // CN OID: 2.5.4.3
  const cnOid = new Uint8Array([0x55, 0x04, 0x03]);
  const cnValue = new TextEncoder().encode(commonName);

  // Build AttributeTypeAndValue
  const atv = encodeSequence([
    encodeOid(cnOid),
    encodePrintableString(cnValue),
  ]);

  // Build RDN (SET OF AttributeTypeAndValue)
  const rdn = encodeSet([atv]);

  // Build Name (SEQUENCE OF RDN)
  return encodeSequence([rdn]);
}

function encodeCsrInfo(
  subject: Uint8Array,
  publicKeyInfo: Uint8Array,
  dnsNames: string[],
): Uint8Array {
  const version = new Uint8Array([0x02, 0x01, 0x00]); // INTEGER 0

  const parts = [version, subject, publicKeyInfo];

  // Add extensions if there are SANs
  if (dnsNames.length > 0) {
    const extensions = encodeExtensions(dnsNames);
    parts.push(encodeContextSpecific(0, extensions));
  }

  return encodeSequence(parts);
}

function encodeExtensions(dnsNames: string[]): Uint8Array {
  // Extension request OID: 1.2.840.113549.1.9.14
  const extReqOid = new Uint8Array([
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e,
  ]);

  // SAN OID: 2.5.29.17
  const sanOid = new Uint8Array([0x55, 0x1d, 0x11]);

  // Build SAN value
  const sanValues = dnsNames.map((name) => {
    const nameBytes = new TextEncoder().encode(name);
    return encodeContextSpecific(2, nameBytes, false);
  });
  const sanSequence = encodeSequence(sanValues);
  const sanExtension = encodeSequence([
    encodeOid(sanOid),
    encodeOctetString(sanSequence),
  ]);

  const extensionsSeq = encodeSequence([sanExtension]);

  return encodeSequence([
    encodeOid(extReqOid),
    encodeSet([extensionsSeq]),
  ]);
}

function encodeCsr(csrInfo: Uint8Array, signature: Uint8Array): Uint8Array {
  // SHA-256 with RSA OID: 1.2.840.113549.1.1.11
  const sha256RsaOid = new Uint8Array([
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
  ]);

  const signatureAlgorithm = encodeSequence([
    encodeOid(sha256RsaOid),
    new Uint8Array([0x05, 0x00]), // NULL
  ]);

  const signatureBitString = encodeBitString(signature);

  return encodeSequence([csrInfo, signatureAlgorithm, signatureBitString]);
}

// ASN.1 encoding helpers
function encodeLength(length: number): Uint8Array {
  if (length < 128) {
    return new Uint8Array([length]);
  } else if (length < 256) {
    return new Uint8Array([0x81, length]);
  } else {
    return new Uint8Array([0x82, (length >> 8) & 0xff, length & 0xff]);
  }
}

function encodeSequence(items: Uint8Array[]): Uint8Array {
  const content = concatArrays(items);
  const length = encodeLength(content.length);
  return concatArrays([new Uint8Array([0x30]), length, content]);
}

function encodeSet(items: Uint8Array[]): Uint8Array {
  const content = concatArrays(items);
  const length = encodeLength(content.length);
  return concatArrays([new Uint8Array([0x31]), length, content]);
}

function encodeOid(oid: Uint8Array): Uint8Array {
  const length = encodeLength(oid.length);
  return concatArrays([new Uint8Array([0x06]), length, oid]);
}

function encodePrintableString(value: Uint8Array): Uint8Array {
  const length = encodeLength(value.length);
  return concatArrays([new Uint8Array([0x13]), length, value]);
}

function encodeOctetString(value: Uint8Array): Uint8Array {
  const length = encodeLength(value.length);
  return concatArrays([new Uint8Array([0x04]), length, value]);
}

function encodeBitString(value: Uint8Array): Uint8Array {
  const length = encodeLength(value.length + 1);
  return concatArrays([
    new Uint8Array([0x03]),
    length,
    new Uint8Array([0x00]), // no unused bits
    value,
  ]);
}

function encodeContextSpecific(
  tag: number,
  value: Uint8Array,
  constructed: boolean = true,
): Uint8Array {
  const tagByte = 0xa0 | tag | (constructed ? 0x20 : 0x00);
  const length = encodeLength(value.length);
  return concatArrays([new Uint8Array([tagByte]), length, value]);
}

function concatArrays(arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}
