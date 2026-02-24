// @ts-ignore - node-forge types may not be installed
import forge from 'node-forge';

export interface KeyPairResult {
  privateKeyPem: string;
  publicKeyPem: string;
}

export interface CsrResult {
  csrPem: string;
  privateKeyPem: string;
}

export interface CsrOptions {
  commonName: string;
  dnsNames?: string[];
  ipAddresses?: string[];
  keyType?: 'RSA' | 'ECDSA';
  keySize?: number;
}

/**
 * Generate an RSA key pair
 * @param bits Key size in bits (default: 2048)
 * @returns Promise with PEM-encoded private and public keys
 */
export async function generateRsaKeyPair(bits: number = 2048): Promise<KeyPairResult> {
  return new Promise((resolve, reject) => {
    forge.pki.rsa.generateKeyPair({ bits, workers: -1 }, (err: any, keypair: any) => {
      if (err) {
        reject(new Error(`Failed to generate RSA key pair: ${err.message}`));
        return;
      }

      const privateKeyPem = forge.pki.privateKeyToPem(keypair.privateKey);
      const publicKeyPem = forge.pki.publicKeyToPem(keypair.publicKey);

      resolve({ privateKeyPem, publicKeyPem });
    });
  });
}

/**
 * Generate a Certificate Signing Request (CSR)
 * @param options CSR options including subject and SANs
 * @returns Promise with PEM-encoded CSR and private key
 */
export async function generateCsr(options: CsrOptions): Promise<CsrResult> {
  const { commonName, dnsNames = [], ipAddresses = [], keyType = 'RSA', keySize = 2048 } = options;

  // Currently only RSA is supported by node-forge for CSR generation
  // ECDSA support would require a different library
  if (keyType === 'ECDSA') {
    throw new Error('ECDSA key generation is not supported in the browser. Please use RSA or let the server generate the key.');
  }

  // Generate key pair
  const keyPair = await generateRsaKeyPair(keySize);

  // Parse the private key back to forge format
  const privateKey = forge.pki.privateKeyFromPem(keyPair.privateKeyPem);
  const publicKey = forge.pki.publicKeyFromPem(keyPair.publicKeyPem);

  // Create CSR
  const csr = forge.pki.createCertificationRequest();
  csr.publicKey = publicKey;

  // Set subject
  csr.setSubject([
    {
      name: 'commonName',
      value: commonName,
    },
  ]);

  // Add Subject Alternative Names (SANs) if provided
  const altNames: Array<{ type: number; value?: string; ip?: string }> = [];

  // Add DNS names
  for (const dns of dnsNames) {
    if (dns.trim()) {
      altNames.push({ type: 2, value: dns.trim() }); // type 2 = DNS
    }
  }

  // Add IP addresses
  for (const ip of ipAddresses) {
    if (ip.trim()) {
      altNames.push({ type: 7, ip: ip.trim() }); // type 7 = IP
    }
  }

  // Set extensions if we have SANs
  if (altNames.length > 0) {
    csr.setAttributes([
      {
        name: 'extensionRequest',
        extensions: [
          {
            name: 'subjectAltName',
            altNames,
          },
        ],
      },
    ]);
  }

  // Sign the CSR with the private key
  csr.sign(privateKey, forge.md.sha256.create());

  // Convert to PEM
  const csrPem = forge.pki.certificationRequestToPem(csr);

  return {
    csrPem,
    privateKeyPem: keyPair.privateKeyPem,
  };
}

/**
 * Download a file to the user's computer
 * @param content File content
 * @param filename Filename to save as
 * @param mimeType MIME type of the file
 */
export function downloadFile(content: string, filename: string, mimeType: string = 'application/x-pem-file'): void {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}
