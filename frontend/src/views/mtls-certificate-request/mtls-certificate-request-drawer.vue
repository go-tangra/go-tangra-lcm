<script lang="ts" setup>
import { ref, computed } from 'vue';

import { useVbenDrawer } from 'shell/vben/common-ui';

import { Descriptions, DescriptionsItem, Tag, Divider, Typography } from 'ant-design-vue';

// MtlsCertificateRequest type from store
import type { MtlsCertificateRequest } from '../../stores/lcm-mtls-certificate-request.state';
import { $t } from 'shell/locales';

const { Paragraph, Text } = Typography;

const data = ref<{ row: MtlsCertificateRequest }>();

const title = computed(() => $t('lcm.page.certificateRequest.details'));

function statusToColor(status: string | undefined) {
  switch (status) {
    case 'MTLS_CERTIFICATE_REQUEST_STATUS_PENDING':
      return '#FAAD14';
    case 'MTLS_CERTIFICATE_REQUEST_STATUS_APPROVED':
      return '#1890FF';
    case 'MTLS_CERTIFICATE_REQUEST_STATUS_REJECTED':
      return '#FF4D4F';
    case 'MTLS_CERTIFICATE_REQUEST_STATUS_ISSUED':
      return '#52C41A';
    case 'MTLS_CERTIFICATE_REQUEST_STATUS_CANCELLED':
      return '#8C8C8C';
    default:
      return '#C9CDD4';
  }
}

function statusToName(status: string | undefined) {
  switch (status) {
    case 'MTLS_CERTIFICATE_REQUEST_STATUS_PENDING':
      return $t('lcm.enum.requestStatus.pending');
    case 'MTLS_CERTIFICATE_REQUEST_STATUS_APPROVED':
      return $t('lcm.enum.requestStatus.approved');
    case 'MTLS_CERTIFICATE_REQUEST_STATUS_REJECTED':
      return $t('lcm.enum.requestStatus.rejected');
    case 'MTLS_CERTIFICATE_REQUEST_STATUS_ISSUED':
      return $t('lcm.enum.requestStatus.issued');
    case 'MTLS_CERTIFICATE_REQUEST_STATUS_CANCELLED':
      return $t('lcm.enum.requestStatus.cancelled');
    default:
      return status ?? '';
  }
}

function certTypeToName(certType: string | undefined) {
  switch (certType) {
    case 'MTLS_CERT_TYPE_CLIENT':
      return $t('lcm.enum.certType.client');
    case 'MTLS_CERT_TYPE_INTERNAL':
      return $t('lcm.enum.certType.internal');
    default:
      return certType ?? '-';
  }
}

function formatDateTime(value: string | undefined) {
  if (!value) return '-';
  try {
    return new Date(value).toLocaleString();
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
      data.value = drawerApi.getData() as { row: MtlsCertificateRequest };
    }
  },
});

const request = computed(() => data.value?.row);
</script>

<template>
  <Drawer :title="title" :footer="false">
    <template v-if="request">
      <Descriptions :column="1" bordered size="small">
        <DescriptionsItem :label="$t('lcm.page.certificateRequest.requestId')">
          <Text code copyable>{{ request.requestId }}</Text>
        </DescriptionsItem>
        <DescriptionsItem :label="$t('ui.table.status')">
          <Tag :color="statusToColor(request.status)">
            {{ statusToName(request.status) }}
          </Tag>
        </DescriptionsItem>
        <DescriptionsItem :label="$t('lcm.page.certificateRequest.clientId')">
          {{ request.clientId ?? '-' }}
        </DescriptionsItem>
        <DescriptionsItem :label="$t('lcm.page.certificateRequest.commonName')">
          {{ request.commonName ?? '-' }}
        </DescriptionsItem>
        <DescriptionsItem :label="$t('lcm.page.certificateRequest.issuerName')">
          {{ request.issuerName ?? '-' }}
        </DescriptionsItem>
        <DescriptionsItem :label="$t('lcm.page.certificateRequest.certType')">
          {{ certTypeToName(request.certType) }}
        </DescriptionsItem>
        <DescriptionsItem :label="$t('lcm.page.certificateRequest.validityDays')">
          {{ request.validityDays ?? '-' }}
        </DescriptionsItem>
      </Descriptions>

      <template v-if="request.dnsNames?.length || request.ipAddresses?.length">
        <Divider>{{ $t('lcm.page.certificateRequest.sans') }}</Divider>
        <Descriptions :column="1" bordered size="small">
          <DescriptionsItem v-if="request.dnsNames?.length" :label="$t('lcm.page.certificateRequest.dnsNames')">
            <div>
              <Tag v-for="name in request.dnsNames" :key="name" style="margin: 2px;">
                {{ name }}
              </Tag>
            </div>
          </DescriptionsItem>
          <DescriptionsItem v-if="request.ipAddresses?.length" :label="$t('lcm.page.certificateRequest.ipAddresses')">
            <div>
              <Tag v-for="ip in request.ipAddresses" :key="ip" style="margin: 2px;">
                {{ ip }}
              </Tag>
            </div>
          </DescriptionsItem>
        </Descriptions>
      </template>

      <template v-if="request.csrPem">
        <Divider>{{ $t('lcm.page.certificateRequest.csrInfo') }}</Divider>
        <Descriptions :column="1" bordered size="small">
          <DescriptionsItem :label="$t('lcm.page.certificateRequest.csrPem')">
            <Paragraph
              :copyable="{ text: request.csrPem }"
              style="margin-bottom: 0; font-family: monospace; font-size: 11px; max-height: 150px; overflow: auto;"
            >
              <pre style="margin: 0; white-space: pre-wrap; word-break: break-all;">{{ request.csrPem }}</pre>
            </Paragraph>
          </DescriptionsItem>
        </Descriptions>
      </template>

      <Divider>{{ $t('lcm.page.certificateRequest.timestamps') }}</Divider>
      <Descriptions :column="2" bordered size="small">
        <DescriptionsItem :label="$t('ui.table.createdAt')">
          {{ formatDateTime(request.createTime as string) }}
        </DescriptionsItem>
        <DescriptionsItem :label="$t('lcm.page.certificateRequest.expiresAt')">
          {{ formatDateTime(request.expiresAt as string) }}
        </DescriptionsItem>
        <DescriptionsItem v-if="request.approvedAt" :label="$t('lcm.page.certificateRequest.approvedAt')">
          {{ formatDateTime(request.approvedAt as string) }}
        </DescriptionsItem>
        <DescriptionsItem v-if="request.rejectedAt" :label="$t('lcm.page.certificateRequest.rejectedAt')">
          {{ formatDateTime(request.rejectedAt as string) }}
        </DescriptionsItem>
      </Descriptions>

      <template v-if="request.status === 'MTLS_CERTIFICATE_REQUEST_STATUS_REJECTED' && request.rejectReason">
        <Divider>{{ $t('lcm.page.certificateRequest.rejectionInfo') }}</Divider>
        <Descriptions :column="1" bordered size="small">
          <DescriptionsItem :label="$t('lcm.page.certificateRequest.rejectReason')">
            <Text type="danger">{{ request.rejectReason }}</Text>
          </DescriptionsItem>
        </Descriptions>
      </template>

      <template v-if="request.status === 'MTLS_CERTIFICATE_REQUEST_STATUS_ISSUED' && request.certificateSerial">
        <Divider>{{ $t('lcm.page.certificateRequest.issuedCertificate') }}</Divider>
        <Descriptions :column="1" bordered size="small">
          <DescriptionsItem :label="$t('lcm.page.certificateRequest.certificateSerial')">
            <Text code copyable>{{ request.certificateSerial }}</Text>
          </DescriptionsItem>
        </Descriptions>
      </template>

      <template v-if="request.notes">
        <Divider>{{ $t('lcm.page.certificateRequest.notes') }}</Divider>
        <Descriptions :column="1" bordered size="small">
          <DescriptionsItem :label="$t('lcm.page.certificateRequest.notes')">
            {{ request.notes }}
          </DescriptionsItem>
        </Descriptions>
      </template>
    </template>
  </Drawer>
</template>
