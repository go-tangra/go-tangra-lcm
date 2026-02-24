import { defineStore } from 'pinia';

import {
  IssuerService,
  DnsProviderService,
  type ListIssuersResponse,
  type GetIssuerInfoResponse,
  type CreateIssuerResponse,
  type CreateIssuerRequest,
  type UpdateIssuerRequest,
  type ListDnsProvidersResponse,
  type DnsProviderInfo,
} from '../api/services';

export const useLcmIssuerStore = defineStore('lcm-issuer', () => {
  /**
   * List issuers
   */
  async function listIssuers(): Promise<ListIssuersResponse> {
    return await IssuerService.list();
  }

  /**
   * Get issuer by name
   */
  async function getIssuer(issuerName: string): Promise<GetIssuerInfoResponse> {
    return await IssuerService.get(issuerName);
  }

  /**
   * Create a new issuer
   */
  async function createIssuer(
    request: CreateIssuerRequest,
  ): Promise<CreateIssuerResponse> {
    return await IssuerService.create(request);
  }

  /**
   * Update an issuer
   */
  async function updateIssuer(
    request: UpdateIssuerRequest,
  ): Promise<void> {
    return await IssuerService.update(request.name!, request);
  }

  /**
   * Delete an issuer
   */
  async function deleteIssuer(name: string): Promise<void> {
    return await IssuerService.delete(name);
  }

  /**
   * List DNS providers
   */
  async function listDnsProviders(): Promise<ListDnsProvidersResponse> {
    return await DnsProviderService.list();
  }

  /**
   * Get DNS provider by name
   */
  async function getDnsProvider(name: string): Promise<DnsProviderInfo> {
    return await DnsProviderService.get(name);
  }

  function $reset() {}

  return {
    $reset,
    listIssuers,
    getIssuer,
    createIssuer,
    updateIssuer,
    deleteIssuer,
    listDnsProviders,
    getDnsProvider,
  };
});
