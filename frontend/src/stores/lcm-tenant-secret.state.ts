import { defineStore } from 'pinia';

import {
  TenantSecretService,
  type TenantSecretStatus,
  type ListTenantSecretsResponse,
  type GetTenantSecretResponse,
  type CreateTenantSecretResponse,
  type UpdateTenantSecretResponse,
  type RotateTenantSecretResponse,
} from '../api/services';

interface Paging { page: number; pageSize: number; }

export const useLcmTenantSecretStore = defineStore('lcm-tenant-secret', () => {
  /**
   * List tenant secrets
   */
  async function listTenantSecrets(
    paging?: Paging,
    formValues?: {
      tenantId?: number;
      status?: TenantSecretStatus;
    } | null,
  ): Promise<ListTenantSecretsResponse> {
    return await TenantSecretService.list({
      tenantId: formValues?.tenantId,
      status: formValues?.status,
      page: paging?.page,
      pageSize: paging?.pageSize,
    });
  }

  /**
   * Get tenant secret by ID
   */
  async function getTenantSecret(id: number): Promise<GetTenantSecretResponse> {
    return await TenantSecretService.get(id);
  }

  /**
   * Create tenant secret
   */
  async function createTenantSecret(data: {
    tenantId: number;
    secret: string;
    description?: string;
    expiresAt?: string;
  }): Promise<CreateTenantSecretResponse> {
    return await TenantSecretService.create(data);
  }

  /**
   * Update tenant secret
   */
  async function updateTenantSecret(
    id: number,
    data: {
      description?: string;
      status?: TenantSecretStatus;
      expiresAt?: string;
    },
  ): Promise<UpdateTenantSecretResponse> {
    return await TenantSecretService.update(id, data);
  }

  /**
   * Delete tenant secret
   */
  async function deleteTenantSecret(id: number): Promise<void> {
    return await TenantSecretService.delete(id);
  }

  /**
   * Rotate tenant secret
   */
  async function rotateTenantSecret(
    id: number,
    newSecret: string,
    disableOld?: boolean,
  ): Promise<RotateTenantSecretResponse> {
    return await TenantSecretService.rotate(id, { newSecret, disableOld });
  }

  function $reset() {}

  return {
    $reset,
    listTenantSecrets,
    getTenantSecret,
    createTenantSecret,
    updateTenantSecret,
    deleteTenantSecret,
    rotateTenantSecret,
  };
});
