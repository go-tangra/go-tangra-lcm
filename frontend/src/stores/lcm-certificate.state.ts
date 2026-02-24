import { defineStore } from 'pinia';

import {
  CertificateJobService,
  type CertificateJobStatus,
  type ListJobsResponse,
  type GetJobStatusResponse,
  type GetJobResultResponse,
  type RequestCertificateResponse,
  type RequestCertificateRequest,
} from '../api/services';
import { lcmApi } from '../api/client';

interface Paging { page: number; pageSize: number; }

// mTLS certificate types (matching proto definitions)
type MtlsCertificateStatus =
  | 'MTLS_CERTIFICATE_STATUS_UNSPECIFIED'
  | 'MTLS_CERTIFICATE_STATUS_ACTIVE'
  | 'MTLS_CERTIFICATE_STATUS_EXPIRED'
  | 'MTLS_CERTIFICATE_STATUS_REVOKED'
  | 'MTLS_CERTIFICATE_STATUS_SUSPENDED';

type MtlsCertificateRevocationReason =
  | 'MTLS_CERT_REVOCATION_REASON_UNSPECIFIED'
  | 'MTLS_CERT_REVOCATION_REASON_KEY_COMPROMISE'
  | 'MTLS_CERT_REVOCATION_REASON_CA_COMPROMISE'
  | 'MTLS_CERT_REVOCATION_REASON_AFFILIATION_CHANGED'
  | 'MTLS_CERT_REVOCATION_REASON_SUPERSEDED'
  | 'MTLS_CERT_REVOCATION_REASON_CESSATION_OF_OPERATION'
  | 'MTLS_CERT_REVOCATION_REASON_CERTIFICATE_HOLD'
  | 'MTLS_CERT_REVOCATION_REASON_PRIVILEGE_WITHDRAWN'
  | 'MTLS_CERT_REVOCATION_REASON_AA_COMPROMISE';

export interface MtlsCertificate {
  serialNumber?: string;
  clientId?: string;
  commonName?: string;
  tenantId?: number;
  subjectDn?: string;
  issuerDn?: string;
  issuerName?: string;
  fingerprintSha256?: string;
  fingerprintSha1?: string;
  publicKeyAlgorithm?: string;
  publicKeySize?: number;
  signatureAlgorithm?: string;
  certificatePem?: string;
  publicKeyPem?: string;
  dnsNames?: string[];
  ipAddresses?: string[];
  emailAddresses?: string[];
  uris?: string[];
  certType?: string;
  status?: MtlsCertificateStatus;
  isCa?: boolean;
  pathLenConstraint?: number;
  keyUsage?: string[];
  extKeyUsage?: string[];
  metadata?: Record<string, string>;
  notes?: string;
  requestId?: number;
  revocationReason?: MtlsCertificateRevocationReason;
  revocationNotes?: string;
  issuedBy?: number;
  revokedBy?: number;
  createdBy?: number;
  updatedBy?: number;
  notBefore?: string;
  notAfter?: string;
  issuedAt?: string;
  revokedAt?: string;
  lastSeenAt?: string;
  createTime?: string;
  updateTime?: string;
  deleteTime?: string;
}

interface ListMtlsCertificatesResponse {
  items?: MtlsCertificate[];
  total?: number;
}

interface DownloadMtlsCertificateResponse {
  certificatePem?: string;
  chainPem?: string;
  caCertificatePem?: string;
}

interface RevokeMtlsCertificateResponse {
  mtlsCertificate?: MtlsCertificate;
}

// Helper to build query string
function buildQuery(params: Record<string, unknown>): string {
  const searchParams = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') {
      searchParams.append(key, String(value));
    }
  }
  const query = searchParams.toString();
  return query ? `?${query}` : '';
}

export const useLcmCertificateStore = defineStore('lcm-certificate', () => {
  /**
   * List mTLS certificates (via certificate jobs)
   */
  async function listCertificates(
    paging?: Paging,
    formValues?: {
      issuerName?: string;
      status?: CertificateJobStatus;
      tenantId?: number;
    } | null,
  ): Promise<ListJobsResponse> {
    return await CertificateJobService.list({
      tenantId: formValues?.tenantId,
      issuerName: formValues?.issuerName,
      status: formValues?.status,
      page: paging?.page,
      pageSize: paging?.pageSize,
    });
  }

  /**
   * Get certificate job status
   */
  async function getJobStatus(jobId: string): Promise<GetJobStatusResponse> {
    return await CertificateJobService.getStatus(jobId);
  }

  /**
   * Get certificate job result
   */
  async function getJobResult(
    jobId: string,
    includePrivateKey?: boolean,
  ): Promise<GetJobResultResponse> {
    return await CertificateJobService.getResult(jobId, { includePrivateKey });
  }

  /**
   * Request a new certificate
   */
  async function requestCertificate(
    request: RequestCertificateRequest,
  ): Promise<RequestCertificateResponse> {
    return await CertificateJobService.requestCertificate(request);
  }

  /**
   * Cancel a pending certificate job
   */
  async function cancelJob(jobId: string): Promise<void> {
    return await CertificateJobService.cancel(jobId);
  }

  /**
   * List mTLS certificates (admin view)
   */
  async function listMtlsCertificates(
    paging?: Paging,
    formValues?: {
      commonName?: string;
      clientId?: string;
      status?: MtlsCertificateStatus;
      includeExpired?: boolean;
      includeRevoked?: boolean;
    } | null,
  ): Promise<{ items: MtlsCertificate[]; total: number }> {
    const resp = await lcmApi.get<ListMtlsCertificatesResponse>(
      `/certificates${buildQuery({
        commonName: formValues?.commonName,
        clientId: formValues?.clientId,
        status: formValues?.status,
        includeExpired: formValues?.includeExpired,
        includeRevoked: formValues?.includeRevoked,
        page: paging?.page,
        pageSize: paging?.pageSize,
      })}`,
    );
    return {
      items: resp.items ?? [],
      total: resp.total ?? 0,
    };
  }

  /**
   * Download mTLS certificate PEM
   */
  async function downloadCertificate(
    serialNumber: string,
    includeChain?: boolean,
  ): Promise<DownloadMtlsCertificateResponse> {
    return await lcmApi.get<DownloadMtlsCertificateResponse>(
      `/certificates/${serialNumber}/download${buildQuery({ includeChain })}`,
    );
  }

  /**
   * Revoke mTLS certificate
   */
  async function revokeCertificate(
    serialNumber: string,
    reason: MtlsCertificateRevocationReason,
    notes?: string,
  ): Promise<RevokeMtlsCertificateResponse> {
    return await lcmApi.post<RevokeMtlsCertificateResponse>(
      `/certificates/${serialNumber}/revoke`,
      { reason, notes },
    );
  }

  function $reset() {}

  return {
    $reset,
    listCertificates,
    getJobStatus,
    getJobResult,
    requestCertificate,
    cancelJob,
    listMtlsCertificates,
    downloadCertificate,
    revokeCertificate,
  };
});
