import { defineStore } from 'pinia';

import {
  IssuedCertificateService,
  type IssuedCertificateInfo,
  type GetIssuedCertificateResponse,
  type ForceRenewCertificateResponse,
} from '../api/services';

interface Paging { page: number; pageSize: number; }

export const useLcmIssuedCertificateStore = defineStore('lcm-issued-certificate', () => {
  /**
   * List issued certificates
   */
  async function listCertificates(
    paging?: Paging,
    formValues?: {
      issuerName?: string;
      status?: string;
      autoRenewEnabled?: boolean | string;
    } | null,
  ): Promise<{ items: IssuedCertificateInfo[]; total: number }> {
    // Convert string 'true'/'false' to boolean for autoRenewEnabled
    let autoRenewEnabled: boolean | undefined;
    if (formValues?.autoRenewEnabled !== undefined && formValues.autoRenewEnabled !== null && formValues.autoRenewEnabled !== '') {
      autoRenewEnabled = formValues.autoRenewEnabled === true || formValues.autoRenewEnabled === 'true';
    }

    const resp = await IssuedCertificateService.list({
      issuerName: formValues?.issuerName,
      status: formValues?.status,
      autoRenewEnabled,
      page: paging?.page,
      pageSize: paging?.pageSize,
    });
    return {
      items: resp.certificates ?? [],
      total: resp.total ?? 0,
    };
  }

  /**
   * Get a single issued certificate (with optional PEM data)
   */
  async function getCertificate(id: string, includePrivateKey?: boolean): Promise<GetIssuedCertificateResponse> {
    return await IssuedCertificateService.get(id, { includePrivateKey });
  }

  /**
   * Force renew a certificate
   */
  async function renewCertificate(id: string): Promise<ForceRenewCertificateResponse> {
    return await IssuedCertificateService.renew(id);
  }

  function $reset() {}

  return {
    $reset,
    listCertificates,
    getCertificate,
    renewCertificate,
  };
});
