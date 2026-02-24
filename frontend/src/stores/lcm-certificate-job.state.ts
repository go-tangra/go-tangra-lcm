import { defineStore } from 'pinia';

import {
  CertificateJobService,
  type CertificateJobStatus,
  type CertificateJobInfo,
  type GetJobStatusResponse,
  type GetJobResultResponse,
  type RequestCertificateResponse,
  type RequestCertificateRequest,
} from '../api/services';

interface Paging { page: number; pageSize: number; }

export const useLcmCertificateJobStore = defineStore('lcm-certificate-job', () => {
  /**
   * List certificate jobs
   */
  async function listJobs(
    paging?: Paging,
    formValues?: {
      issuerName?: string;
      status?: CertificateJobStatus;
      tenantId?: number;
    } | null,
  ): Promise<{ items: CertificateJobInfo[]; total: number }> {
    const resp = await CertificateJobService.list({
      tenantId: formValues?.tenantId,
      issuerName: formValues?.issuerName,
      status: formValues?.status,
      page: paging?.page,
      pageSize: paging?.pageSize,
    });
    return {
      items: resp.jobs ?? [],
      total: resp.total ?? 0,
    };
  }

  /**
   * Get certificate job status
   */
  async function getJobStatus(jobId: string): Promise<GetJobStatusResponse> {
    return await CertificateJobService.getStatus(jobId);
  }

  /**
   * Get certificate job result (includes certificate PEM)
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
   * Cancel a pending job
   */
  async function cancelJob(jobId: string): Promise<void> {
    return await CertificateJobService.cancel(jobId);
  }

  /**
   * Retry a failed job
   */
  async function retryJob(jobId: string): Promise<RequestCertificateResponse> {
    return await CertificateJobService.retry(jobId);
  }

  function $reset() {}

  return {
    $reset,
    listJobs,
    getJobStatus,
    getJobResult,
    requestCertificate,
    cancelJob,
    retryJob,
  };
});
