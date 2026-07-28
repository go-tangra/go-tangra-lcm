<script lang="ts" setup>
import { ref, computed } from 'vue';

import { useVbenDrawer } from 'shell/vben/common-ui';

import { Descriptions, DescriptionsItem, Tag, Divider, Typography } from 'ant-design-vue';

import { $t } from 'shell/locales';
import { formatDateTime as formatDateTimeShared } from '../../datetime';

interface AuditLog {
  id?: number;
  auditId?: string;
  tenantId?: number;
  clientId?: string;
  clientCommonName?: string;
  clientOrganization?: string;
  clientSerialNumber?: string;
  isAuthenticated?: boolean;
  operation?: string;
  success?: boolean;
  peerAddress?: string;
  latencyMs?: number;
  requestId?: string;
  serviceName?: string;
  errorCode?: string;
  errorMessage?: string;
  logHash?: string;
  createdAt?: string;
}

const { Text } = Typography;

const data = ref<{ row: AuditLog }>();

const title = computed(() => $t('lcm.page.auditLog.details'));

function successToColor(success: boolean | undefined) {
  if (success === true) {
    return '#52C41A';
  } else if (success === false) {
    return '#FF4D4F';
  }
  return '#C9CDD4';
}

function successToName(success: boolean | undefined) {
  if (success === true) {
    return $t('lcm.enum.successStatus.success');
  } else if (success === false) {
    return $t('lcm.enum.successStatus.failed');
  }
  return '-';
}

function formatDateTime(value: string | undefined) {
  if (!value) return '-';
  try {
    return formatDateTimeShared(value);
  } catch {
    return value;
  }
}

const [Drawer, drawerApi] = useVbenDrawer({
  onCancel() {
    drawerApi.close();
  },

  onOpenChange(isOpen) {
    if (isOpen) {
      data.value = drawerApi.getData() as { row: AuditLog };
    }
  },
});

const log = computed(() => data.value?.row);
</script>

<template>
  <Drawer :title="title" :footer="false">
    <template v-if="log">
      <Descriptions :column="1" bordered size="small">
        <DescriptionsItem :label="$t('lcm.page.auditLog.auditId')">
          <Text code copyable>{{ log.auditId }}</Text>
        </DescriptionsItem>
        <DescriptionsItem :label="$t('lcm.page.auditLog.requestId')">
          <Text v-if="log.requestId" code copyable>{{ log.requestId }}</Text>
          <span v-else>-</span>
        </DescriptionsItem>
        <DescriptionsItem :label="$t('lcm.page.auditLog.operation')">
          {{ log.operation ?? '-' }}
        </DescriptionsItem>
        <DescriptionsItem :label="$t('lcm.page.auditLog.serviceName')">
          {{ log.serviceName ?? '-' }}
        </DescriptionsItem>
        <DescriptionsItem :label="$t('lcm.page.auditLog.success')">
          <Tag :color="successToColor(log.success)">
            {{ successToName(log.success) }}
          </Tag>
        </DescriptionsItem>
      </Descriptions>

      <Divider>{{ $t('lcm.page.auditLog.clientInfo') }}</Divider>

      <Descriptions :column="1" bordered size="small">
        <DescriptionsItem :label="$t('lcm.page.auditLog.clientId')">
          {{ log.clientId ?? '-' }}
        </DescriptionsItem>
        <DescriptionsItem :label="$t('lcm.page.auditLog.clientCommonName')">
          {{ log.clientCommonName ?? '-' }}
        </DescriptionsItem>
        <DescriptionsItem :label="$t('lcm.page.auditLog.clientOrganization')">
          {{ log.clientOrganization ?? '-' }}
        </DescriptionsItem>
        <DescriptionsItem :label="$t('lcm.page.auditLog.clientSerialNumber')">
          {{ log.clientSerialNumber ?? '-' }}
        </DescriptionsItem>
        <DescriptionsItem :label="$t('lcm.page.auditLog.isAuthenticated')">
          <Tag :color="log.isAuthenticated ? '#52C41A' : '#8C8C8C'">
            {{ log.isAuthenticated ? $t('lcm.enum.authenticated.yes') : $t('lcm.enum.authenticated.no') }}
          </Tag>
        </DescriptionsItem>
      </Descriptions>

      <template v-if="log.success === false">
        <Divider>{{ $t('lcm.page.auditLog.errorInfo') }}</Divider>
        <Descriptions :column="1" bordered size="small">
          <DescriptionsItem :label="$t('lcm.page.auditLog.errorCode')">
            {{ log.errorCode ?? '-' }}
          </DescriptionsItem>
          <DescriptionsItem :label="$t('lcm.page.auditLog.errorMessage')">
            {{ log.errorMessage ?? '-' }}
          </DescriptionsItem>
        </Descriptions>
      </template>

      <Divider>{{ $t('lcm.page.auditLog.networkInfo') }}</Divider>

      <Descriptions :column="2" bordered size="small">
        <DescriptionsItem :label="$t('lcm.page.auditLog.peerAddress')">
          {{ log.peerAddress ?? '-' }}
        </DescriptionsItem>
        <DescriptionsItem :label="$t('lcm.page.auditLog.latencyMs')">
          {{ log.latencyMs !== undefined ? `${log.latencyMs} ms` : '-' }}
        </DescriptionsItem>
      </Descriptions>

      <Divider>{{ $t('lcm.page.auditLog.timestamps') }}</Divider>

      <Descriptions :column="1" bordered size="small">
        <DescriptionsItem :label="$t('ui.table.createdAt')">
          {{ formatDateTime(log.createdAt) }}
        </DescriptionsItem>
        <DescriptionsItem v-if="log.logHash" :label="$t('lcm.page.auditLog.logHash')">
          <Text code style="font-size: 11px; word-break: break-all;">{{ log.logHash }}</Text>
        </DescriptionsItem>
      </Descriptions>
    </template>
  </Drawer>
</template>
