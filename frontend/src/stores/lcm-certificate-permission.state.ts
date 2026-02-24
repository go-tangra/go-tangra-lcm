import { defineStore } from 'pinia';

import {
  CertificatePermissionService,
  type PermissionType,
  type ListAccessibleCertificatesResponse,
  type ListPermissionsResponse,
  type GrantPermissionResponse,
  type CheckPermissionResponse,
  type CertificatePermission,
} from '../api/services';
import { lcmApi } from '../api/client';

interface Paging { page: number; pageSize: number; }

interface ListAllPermissionsResponse {
  permissions?: CertificatePermission[];
  total?: number;
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

export const useLcmCertificatePermissionStore = defineStore(
  'lcm-certificate-permission',
  () => {
    /**
     * List certificates accessible to the authenticated client
     */
    async function listAccessibleCertificates(
      formValues?: {
        permissionType?: PermissionType;
        includeExpired?: boolean;
      } | null,
    ): Promise<ListAccessibleCertificatesResponse> {
      return await CertificatePermissionService.listAccessible({
        permissionType: formValues?.permissionType,
        includeExpired: formValues?.includeExpired,
      });
    }

    /**
     * List permissions for a specific certificate
     */
    async function listPermissionsForCertificate(
      certificateId: string,
    ): Promise<ListPermissionsResponse> {
      return await CertificatePermissionService.listPermissions(certificateId);
    }

    /**
     * Check if the authenticated client has permission to access a certificate
     */
    async function checkPermission(
      certificateId: string,
    ): Promise<CheckPermissionResponse> {
      return await CertificatePermissionService.check(certificateId);
    }

    /**
     * Grant permission to a client
     */
    async function grantPermission(
      certificateId: string,
      granteeClientId: string,
      permissionType: PermissionType,
      expiresAt?: string,
    ): Promise<GrantPermissionResponse> {
      return await CertificatePermissionService.grant({
        certificateId,
        granteeClientId,
        permissionType,
        expiresAt,
      });
    }

    /**
     * Revoke permission from a client
     */
    async function revokePermission(
      certificateId: string,
      granteeClientId: string,
    ): Promise<void> {
      return await CertificatePermissionService.revoke(certificateId, granteeClientId);
    }

    /**
     * List all permissions (admin view)
     */
    async function listAllPermissions(
      _paging?: Paging,
      formValues?: {
        certificateId?: string;
        granteeClientId?: string;
      } | null,
    ): Promise<{ items: CertificatePermission[]; total: number }> {
      const resp = await lcmApi.get<ListAllPermissionsResponse>(
        `/certificate-permissions/all${buildQuery({
          certificateId: formValues?.certificateId,
          granteeClientId: formValues?.granteeClientId,
        })}`,
      );
      return {
        items: (resp.permissions ?? []) as CertificatePermission[],
        total: resp.total ?? 0,
      };
    }

    function $reset() {}

    return {
      $reset,
      listAccessibleCertificates,
      listPermissionsForCertificate,
      checkPermission,
      grantPermission,
      revokePermission,
      listAllPermissions,
    };
  },
);
