import { defineStore } from 'pinia';

import { lcmApi } from '../api/client';

interface Paging { page: number; pageSize: number; }

// Audit log types (not in OpenAPI spec, using direct API calls)
interface AuditLog {
  id?: number;
  auditId?: string;
  tenantId?: number;
  clientId?: string;
  operation?: string;
  success?: boolean;
  peerAddress?: string;
  details?: string;
  createdAt?: string;
}

interface ListAuditLogsResponse {
  items?: AuditLog[];
  total?: number;
}

interface GetAuditLogResponse {
  auditLog?: AuditLog;
}

interface AuditStats {
  totalLogs?: number;
  successCount?: number;
  failureCount?: number;
  operationCounts?: Record<string, number>;
}

interface GetAuditStatsResponse {
  stats?: AuditStats;
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

export const useLcmAuditLogStore = defineStore('lcm-audit-log', () => {
  /**
   * List audit logs
   */
  async function listAuditLogs(
    paging?: Paging,
    formValues?: {
      clientId?: string;
      endTime?: string;
      operation?: string;
      peerAddress?: string;
      startTime?: string;
      success?: boolean;
      tenantId?: number;
    } | null,
  ): Promise<ListAuditLogsResponse> {
    return await lcmApi.get<ListAuditLogsResponse>(
      `/audit-logs${buildQuery({
        tenantId: formValues?.tenantId,
        clientId: formValues?.clientId,
        operation: formValues?.operation,
        success: formValues?.success,
        peerAddress: formValues?.peerAddress,
        startTime: formValues?.startTime,
        endTime: formValues?.endTime,
        page: paging?.page,
        pageSize: paging?.pageSize,
      })}`,
    );
  }

  /**
   * Get audit log by ID
   */
  async function getAuditLog(id: number): Promise<GetAuditLogResponse> {
    return await lcmApi.get<GetAuditLogResponse>(`/audit-logs/${id}`);
  }

  /**
   * Get audit log by audit ID (UUID)
   */
  async function getAuditLogByAuditId(auditId: string): Promise<GetAuditLogResponse> {
    return await lcmApi.get<GetAuditLogResponse>(`/audit-logs/by-audit-id/${auditId}`);
  }

  /**
   * Get audit statistics
   */
  async function getAuditStats(
    formValues?: {
      endTime?: string;
      startTime?: string;
      tenantId?: number;
    } | null,
  ): Promise<GetAuditStatsResponse> {
    return await lcmApi.get<GetAuditStatsResponse>(
      `/audit-logs/stats${buildQuery({
        tenantId: formValues?.tenantId,
        startTime: formValues?.startTime,
        endTime: formValues?.endTime,
      })}`,
    );
  }

  function $reset() {}

  return {
    $reset,
    listAuditLogs,
    getAuditLog,
    getAuditLogByAuditId,
    getAuditStats,
  };
});
