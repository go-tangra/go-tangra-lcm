/**
 * LCM Module Service Functions
 *
 * Typed service methods for the LCM API using dynamic module routing.
 * Base URL: /admin/v1/modules/lcm/v1
 */

import type { components, operations } from './types';
import { lcmApi, type RequestOptions } from './client';

// ==================== Entity Type Aliases ====================

export type AccessibleCertificate = components['schemas']['AccessibleCertificate'];
export type AcmeIssuer = components['schemas']['AcmeIssuer'];
export type CertificateJobInfo = components['schemas']['CertificateJobInfo'];
export type CertificatePermission = components['schemas']['CertificatePermission'];
export type CertificateStatistics = components['schemas']['CertificateStatistics'];
export type CertificateTypeBreakdown = components['schemas']['CertificateTypeBreakdown'];
export type ClientStatistics = components['schemas']['ClientStatistics'];
export type DnsProviderInfo = components['schemas']['DnsProviderInfo'];
export type IssuedCertificateStatistics = components['schemas']['IssuedCertificateStatistics'];
export type IssuerCertificateCount = components['schemas']['IssuerCertificateCount'];
export type IssuerInfo = components['schemas']['IssuerInfo'];
export type IssuerStatistics = components['schemas']['IssuerStatistics'];
export type JobStatistics = components['schemas']['JobStatistics'];
export type JobTimeBreakdown = components['schemas']['JobTimeBreakdown'];
export type MtlsCertificateStatistics = components['schemas']['MtlsCertificateStatistics'];
export type RecentError = components['schemas']['RecentError'];
export type SelfIssuer = components['schemas']['SelfIssuer'];
export type TenantSecret = components['schemas']['TenantSecret'];
export type TenantStatistics = components['schemas']['TenantStatistics'];

// ==================== Enum Types (derived from entity fields) ====================

export type PermissionType = NonNullable<AccessibleCertificate['permissionType']>;
export type AcmeChallengeType = NonNullable<AcmeIssuer['challengeType']>;
export type CertificateJobStatus = NonNullable<CertificateJobInfo['status']>;
export type IssuerStatus = NonNullable<IssuerInfo['status']>;
export type TenantSecretStatus = NonNullable<TenantSecret['status']>;

// ==================== List Response Types ====================

export type ListJobsResponse = components['schemas']['ListJobsResponse'];
export type ListAccessibleCertificatesResponse = components['schemas']['ListAccessibleCertificatesResponse'];
export type ListPermissionsResponse = components['schemas']['ListPermissionsResponse'];
export type ListIssuersResponse = components['schemas']['ListIssuersResponse'];
export type ListTenantSecretsResponse = components['schemas']['ListTenantSecretsResponse'];
export type ListDnsProvidersResponse = components['schemas']['ListDnsProvidersResponse'];

// ==================== Get Response Types ====================

export type GetJobStatusResponse = components['schemas']['GetJobStatusResponse'];
export type GetJobResultResponse = components['schemas']['GetJobResultResponse'];
export type GetIssuerInfoResponse = components['schemas']['GetIssuerInfoResponse'];
export type GetTenantSecretResponse = components['schemas']['GetTenantSecretResponse'];
export type GetStatisticsResponse = components['schemas']['GetStatisticsResponse'];
export type CheckPermissionResponse = components['schemas']['CheckPermissionResponse'];
export type HealthCheckResponse = components['schemas']['HealthCheckResponse'];

// ==================== Create Response Types ====================

export type CreateIssuerResponse = components['schemas']['CreateIssuerResponse'];
export type CreateTenantSecretResponse = components['schemas']['CreateTenantSecretResponse'];
export type RequestCertificateResponse = components['schemas']['RequestCertificateResponse'];
export type GrantPermissionResponse = components['schemas']['GrantPermissionResponse'];

// ==================== Update Response Types ====================

export type UpdateTenantSecretResponse = components['schemas']['UpdateTenantSecretResponse'];
export type RotateTenantSecretResponse = components['schemas']['RotateTenantSecretResponse'];

// ==================== Request Types ====================

export type RequestCertificateRequest = components['schemas']['RequestCertificateRequest'];
export type GrantPermissionRequest = components['schemas']['GrantPermissionRequest'];
export type CreateIssuerRequest = components['schemas']['CreateIssuerRequest'];
export type UpdateIssuerRequest = components['schemas']['UpdateIssuerRequest'];
export type CreateTenantSecretRequest = components['schemas']['CreateTenantSecretRequest'];
export type UpdateTenantSecretRequest = components['schemas']['UpdateTenantSecretRequest'];
export type RotateTenantSecretRequest = components['schemas']['RotateTenantSecretRequest'];

// ==================== Helper Functions ====================

function buildQuery(params: Record<string, unknown>): string {
  const searchParams = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') {
      if (Array.isArray(value)) {
        value.forEach(v => searchParams.append(key, String(v)));
      } else {
        searchParams.append(key, String(value));
      }
    }
  }
  const query = searchParams.toString();
  return query ? `?${query}` : '';
}

// ==================== Certificate Job Service ====================

export const CertificateJobService = {
  list: async (
    params?: operations['LcmCertificateJobService_ListJobs']['parameters']['query'],
    options?: RequestOptions
  ): Promise<ListJobsResponse> => {
    return lcmApi.get<ListJobsResponse>(`/certificate-jobs${buildQuery(params || {})}`, options);
  },

  getStatus: async (jobId: string, options?: RequestOptions): Promise<GetJobStatusResponse> => {
    return lcmApi.get<GetJobStatusResponse>(`/certificate-jobs/${jobId}/status`, options);
  },

  getResult: async (
    jobId: string,
    params?: operations['LcmCertificateJobService_GetJobResult']['parameters']['query'],
    options?: RequestOptions
  ): Promise<GetJobResultResponse> => {
    return lcmApi.get<GetJobResultResponse>(`/certificate-jobs/${jobId}/result${buildQuery(params || {})}`, options);
  },

  requestCertificate: async (
    data: RequestCertificateRequest,
    options?: RequestOptions
  ): Promise<RequestCertificateResponse> => {
    return lcmApi.post<RequestCertificateResponse>('/certificate-jobs', data, options);
  },

  cancel: async (jobId: string, options?: RequestOptions): Promise<void> => {
    return lcmApi.post<void>(`/certificate-jobs/${jobId}/cancel`, undefined, options);
  },

  retry: async (jobId: string, options?: RequestOptions): Promise<RequestCertificateResponse> => {
    return lcmApi.post<RequestCertificateResponse>(`/certificate-jobs/${jobId}/retry`, undefined, options);
  },
};

// ==================== Certificate Permission Service ====================

export const CertificatePermissionService = {
  listAccessible: async (
    params?: operations['CertificatePermissionService_ListAccessibleCertificates']['parameters']['query'],
    options?: RequestOptions
  ): Promise<ListAccessibleCertificatesResponse> => {
    return lcmApi.get<ListAccessibleCertificatesResponse>(
      `/certificate-permissions/accessible${buildQuery(params || {})}`,
      options
    );
  },

  listPermissions: async (
    certificateId: string,
    options?: RequestOptions
  ): Promise<ListPermissionsResponse> => {
    return lcmApi.get<ListPermissionsResponse>(`/certificate-permissions/${certificateId}`, options);
  },

  check: async (
    certificateId: string,
    params?: operations['CertificatePermissionService_CheckPermission']['parameters']['query'],
    options?: RequestOptions
  ): Promise<CheckPermissionResponse> => {
    return lcmApi.get<CheckPermissionResponse>(
      `/certificate-permissions/${certificateId}/check${buildQuery(params || {})}`,
      options
    );
  },

  grant: async (
    data: GrantPermissionRequest,
    options?: RequestOptions
  ): Promise<GrantPermissionResponse> => {
    return lcmApi.post<GrantPermissionResponse>('/certificate-permissions', data, options);
  },

  revoke: async (
    certificateId: string,
    granteeClientId: string,
    options?: RequestOptions
  ): Promise<void> => {
    return lcmApi.delete<void>(
      `/certificate-permissions/${certificateId}/grantees/${granteeClientId}`,
      options
    );
  },
};

// ==================== Issuer Service ====================

export const IssuerService = {
  list: async (options?: RequestOptions): Promise<ListIssuersResponse> => {
    return lcmApi.get<ListIssuersResponse>('/issuers', options);
  },

  get: async (issuerName: string, options?: RequestOptions): Promise<GetIssuerInfoResponse> => {
    return lcmApi.get<GetIssuerInfoResponse>(`/issuers/${issuerName}`, options);
  },

  create: async (
    data: CreateIssuerRequest,
    options?: RequestOptions
  ): Promise<CreateIssuerResponse> => {
    return lcmApi.post<CreateIssuerResponse>('/issuers', data, options);
  },

  update: async (
    name: string,
    data: UpdateIssuerRequest,
    options?: RequestOptions
  ): Promise<void> => {
    return lcmApi.put<void>(`/issuers/${name}`, data, options);
  },

  delete: async (name: string, options?: RequestOptions): Promise<void> => {
    return lcmApi.delete<void>(`/issuers/${name}`, options);
  },
};

// ==================== DNS Provider Service ====================

export const DnsProviderService = {
  list: async (options?: RequestOptions): Promise<ListDnsProvidersResponse> => {
    return lcmApi.get<ListDnsProvidersResponse>('/dns-providers', options);
  },

  get: async (name: string, options?: RequestOptions): Promise<DnsProviderInfo> => {
    return lcmApi.get<DnsProviderInfo>(`/dns-providers/${name}`, options);
  },
};

// ==================== Tenant Secret Service ====================

export const TenantSecretService = {
  list: async (
    params?: operations['TenantSecretService_ListTenantSecrets']['parameters']['query'],
    options?: RequestOptions
  ): Promise<ListTenantSecretsResponse> => {
    return lcmApi.get<ListTenantSecretsResponse>(`/tenant-secrets${buildQuery(params || {})}`, options);
  },

  get: async (id: number, options?: RequestOptions): Promise<GetTenantSecretResponse> => {
    return lcmApi.get<GetTenantSecretResponse>(`/tenant-secrets/${id}`, options);
  },

  create: async (
    data: CreateTenantSecretRequest,
    options?: RequestOptions
  ): Promise<CreateTenantSecretResponse> => {
    return lcmApi.post<CreateTenantSecretResponse>('/tenant-secrets', data, options);
  },

  update: async (
    id: number,
    data: Omit<UpdateTenantSecretRequest, 'id'>,
    options?: RequestOptions
  ): Promise<UpdateTenantSecretResponse> => {
    return lcmApi.put<UpdateTenantSecretResponse>(`/tenant-secrets/${id}`, { ...data, id }, options);
  },

  delete: async (id: number, options?: RequestOptions): Promise<void> => {
    return lcmApi.delete<void>(`/tenant-secrets/${id}`, options);
  },

  rotate: async (
    id: number,
    data: Omit<RotateTenantSecretRequest, 'id'>,
    options?: RequestOptions
  ): Promise<RotateTenantSecretResponse> => {
    return lcmApi.post<RotateTenantSecretResponse>(`/tenant-secrets/${id}/rotate`, { ...data, id }, options);
  },
};

// ==================== Statistics Service ====================

export const StatisticsService = {
  get: async (
    params?: operations['LcmStatisticsService_GetStatistics']['parameters']['query'],
    options?: RequestOptions
  ): Promise<GetStatisticsResponse> => {
    // Note: This endpoint uses /api/v1/lcm path prefix instead of module routing
    return lcmApi.get<GetStatisticsResponse>(`/api/v1/lcm/statistics${buildQuery(params || {})}`, options);
  },

  getTenant: async (
    tenantId: number,
    params?: operations['LcmStatisticsService_GetTenantStatistics']['parameters']['query'],
    options?: RequestOptions
  ): Promise<TenantStatistics> => {
    // Note: This endpoint uses /api/v1/lcm path prefix instead of module routing
    return lcmApi.get<TenantStatistics>(
      `/api/v1/lcm/statistics/tenant/${tenantId}${buildQuery(params || {})}`,
      options
    );
  },
};

// ==================== Issued Certificate Service ====================

export interface IssuedCertificateInfo {
  id?: string;
  commonName?: string;
  domains?: string[];
  issuerName?: string;
  issuerType?: string;
  status?: string;
  expiresAt?: string;
  autoRenewEnabled?: boolean;
  autoRenewDaysBeforeExpiry?: number;
  keyType?: string;
  keySize?: number;
  errorMessage?: string;
  createdAt?: string;
  updatedAt?: string;
}

export interface ListIssuedCertificatesResponse {
  certificates?: IssuedCertificateInfo[];
  total?: number;
}

export interface GetIssuedCertificateResponse {
  certificate?: IssuedCertificateInfo;
  certificatePem?: string;
  caCertificatePem?: string;
  privateKeyPem?: string;
  serverGeneratedKey?: boolean;
}

export interface ForceRenewCertificateResponse {
  renewalId?: string;
  message?: string;
}

export const IssuedCertificateService = {
  list: async (
    params?: {
      status?: string;
      issuerName?: string;
      autoRenewEnabled?: boolean;
      page?: number;
      pageSize?: number;
    },
    options?: RequestOptions
  ): Promise<ListIssuedCertificatesResponse> => {
    return lcmApi.get<ListIssuedCertificatesResponse>(
      `/issued-certificates${buildQuery(params || {})}`,
      options
    );
  },

  get: async (
    id: string,
    params?: { includePrivateKey?: boolean },
    options?: RequestOptions
  ): Promise<GetIssuedCertificateResponse> => {
    return lcmApi.get<GetIssuedCertificateResponse>(
      `/issued-certificates/${id}${buildQuery(params || {})}`,
      options
    );
  },

  renew: async (
    id: string,
    options?: RequestOptions
  ): Promise<ForceRenewCertificateResponse> => {
    return lcmApi.post<ForceRenewCertificateResponse>(
      `/issued-certificates/${id}/renew`,
      undefined,
      options
    );
  },
};

// ==================== mTLS Certificate Service ====================

export interface MtlsCertificate {
  serialNumber?: string;
  clientId?: string;
  commonName?: string;
  tenantId?: number;
  issuerName?: string;
  status?: string;
  certType?: string;
}

export interface ListMtlsCertificatesResponse {
  items?: MtlsCertificate[];
  total?: number;
}

export const MtlsCertificateService = {
  list: async (
    params?: {
      status?: string;
      clientId?: string;
      issuerName?: string;
      commonName?: string;
      includeExpired?: boolean;
      includeRevoked?: boolean;
      page?: number;
      pageSize?: number;
    },
    options?: RequestOptions
  ): Promise<ListMtlsCertificatesResponse> => {
    return lcmApi.get<ListMtlsCertificatesResponse>(
      `/certificates${buildQuery(params || {})}`,
      options
    );
  },
};

// ==================== System Service ====================

export const SystemService = {
  healthCheck: async (options?: RequestOptions): Promise<HealthCheckResponse> => {
    return lcmApi.get<HealthCheckResponse>('/health', options);
  },
};
