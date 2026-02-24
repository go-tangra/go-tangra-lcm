import { defineStore } from 'pinia';

import { lcmApi } from '../api/client';

interface Paging { page: number; pageSize: number; }

// mTLS certificate request types (not in OpenAPI spec, using direct API calls)
type MtlsCertificateRequestStatus =
  | 'MTLS_CERTIFICATE_REQUEST_STATUS_UNSPECIFIED'
  | 'MTLS_CERTIFICATE_REQUEST_STATUS_PENDING'
  | 'MTLS_CERTIFICATE_REQUEST_STATUS_APPROVED'
  | 'MTLS_CERTIFICATE_REQUEST_STATUS_REJECTED'
  | 'MTLS_CERTIFICATE_REQUEST_STATUS_ISSUED';

export interface MtlsCertificateRequest {
  id?: number;
  requestId?: string;
  tenantId?: number;
  clientId?: string;
  clientName?: string;
  issuerName?: string;
  commonName?: string;
  status?: MtlsCertificateRequestStatus;
  notes?: string;
  createdAt?: string;
  updatedAt?: string;
}

interface ListMtlsCertificateRequestsResponse {
  items?: MtlsCertificateRequest[];
  total?: number;
}

interface GetMtlsCertificateRequestResponse {
  request?: MtlsCertificateRequest;
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

export const useLcmMtlsCertificateRequestStore = defineStore(
  'lcm-mtls-certificate-request',
  () => {
    /**
     * List mTLS certificate requests
     */
    async function listRequests(
      paging?: Paging,
      formValues?: {
        clientId?: string;
        issuerName?: string;
        status?: MtlsCertificateRequestStatus;
        tenantId?: number;
      } | null,
    ): Promise<{ items: MtlsCertificateRequest[]; total: number }> {
      const resp = await lcmApi.get<ListMtlsCertificateRequestsResponse>(
        `/mtls-certificate-requests${buildQuery({
          tenantId: formValues?.tenantId,
          status: formValues?.status,
          clientId: formValues?.clientId,
          issuerName: formValues?.issuerName,
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
     * Get mTLS certificate request by ID
     */
    async function getRequest(id: number): Promise<GetMtlsCertificateRequestResponse> {
      return await lcmApi.get<GetMtlsCertificateRequestResponse>(
        `/mtls-certificate-requests/${id}`,
      );
    }

    /**
     * Get mTLS certificate request by request ID (UUID)
     */
    async function getRequestByRequestId(
      requestId: string,
    ): Promise<GetMtlsCertificateRequestResponse> {
      return await lcmApi.get<GetMtlsCertificateRequestResponse>(
        `/mtls-certificate-requests/by-request-id/${requestId}`,
      );
    }

    /**
     * Approve mTLS certificate request
     */
    async function approveRequest(
      id: number,
      options?: {
        issuerName?: string;
        validityDays?: number;
        notes?: string;
      },
    ) {
      return await lcmApi.post(`/mtls-certificate-requests/${id}/approve`, options);
    }

    /**
     * Reject mTLS certificate request
     */
    async function rejectRequest(id: number, reason: string) {
      return await lcmApi.post(`/mtls-certificate-requests/${id}/reject`, { reason });
    }

    /**
     * Delete mTLS certificate request
     */
    async function deleteRequest(id: number): Promise<void> {
      return await lcmApi.delete<void>(`/mtls-certificate-requests/${id}`);
    }

    function $reset() {}

    return {
      $reset,
      listRequests,
      getRequest,
      getRequestByRequestId,
      approveRequest,
      rejectRequest,
      deleteRequest,
    };
  },
);
