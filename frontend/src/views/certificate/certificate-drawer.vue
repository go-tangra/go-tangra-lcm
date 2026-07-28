<script lang="ts" setup>
import { ref, computed } from 'vue';

import { useVbenDrawer } from 'shell/vben/common-ui';

import { Descriptions, DescriptionsItem, Tag, Divider, Typography } from 'ant-design-vue';

import { $t } from 'shell/locales';
import { type MtlsCertificate } from '../../stores/lcm-certificate.state';
import { formatDateTime as formatDateTimeShared } from '../../datetime';

const { Paragraph, Text } = Typography;

const data = ref<{ row: MtlsCertificate }>();

const title = computed(() => $t('lcm.page.certificate.details'));

function statusToColor(status: string | undefined) {
  switch (status) {
    case 'MTLS_CERTIFICATE_STATUS_ACTIVE':
      return '#52C41A';
    case 'MTLS_CERTIFICATE_STATUS_EXPIRED':
      return '#FAAD14';
    case 'MTLS_CERTIFICATE_STATUS_REVOKED':
      return '#FF4D4F';
    case 'MTLS_CERTIFICATE_STATUS_SUSPENDED':
      return '#8C8C8C';
    default:
      return '#C9CDD4';
  }
}

function statusToName(status: string | undefined) {
  switch (status) {
    case 'MTLS_CERTIFICATE_STATUS_ACTIVE':
      return $t('lcm.enum.certificateStatus.active');
    case 'MTLS_CERTIFICATE_STATUS_EXPIRED':
      return $t('lcm.enum.certificateStatus.expired');
    case 'MTLS_CERTIFICATE_STATUS_REVOKED':
      return $t('lcm.enum.certificateStatus.revoked');
    case 'MTLS_CERTIFICATE_STATUS_SUSPENDED':
      return $t('lcm.enum.certificateStatus.suspended');
    default:
      return status ?? '';
  }
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
      data.value = drawerApi.getData() as { row: MtlsCertificate };
    }
  },
});

const cert = computed(() => data.value?.row);
</script>

<template>
  <Drawer :title="title" :footer="false">
    <template v-if="cert">
      <Descriptions :column="1" bordered size="small">
        <DescriptionsItem :label="$t('lcm.page.certificate.serialNumber')">
          <Text code copyable>{{ cert.serialNumber }}</Text>
        </DescriptionsItem>
        <DescriptionsItem :label="$t('lcm.page.certificate.commonName')">
          {{ cert.commonName }}
        </DescriptionsItem>
        <DescriptionsItem :label="$t('lcm.page.certificate.clientId')">
          {{ cert.clientId }}
        </DescriptionsItem>
        <DescriptionsItem :label="$t('ui.table.status')">
          <Tag :color="statusToColor(cert.status)">
            {{ statusToName(cert.status) }}
          </Tag>
        </DescriptionsItem>
        <DescriptionsItem :label="$t('lcm.page.certificate.issuerName')">
          {{ cert.issuerName ?? '-' }}
        </DescriptionsItem>
        <DescriptionsItem :label="$t('lcm.page.certificate.subjectDn')">
          {{ cert.subjectDn ?? '-' }}
        </DescriptionsItem>
        <DescriptionsItem :label="$t('lcm.page.certificate.issuerDn')">
          {{ cert.issuerDn ?? '-' }}
        </DescriptionsItem>
      </Descriptions>

      <Divider>{{ $t('lcm.page.certificate.validity') }}</Divider>

      <Descriptions :column="2" bordered size="small">
        <DescriptionsItem :label="$t('lcm.page.certificate.notBefore')">
          {{ formatDateTime(cert.notBefore) }}
        </DescriptionsItem>
        <DescriptionsItem :label="$t('lcm.page.certificate.notAfter')">
          {{ formatDateTime(cert.notAfter) }}
        </DescriptionsItem>
        <DescriptionsItem :label="$t('lcm.page.certificate.issuedAt')">
          {{ formatDateTime(cert.issuedAt) }}
        </DescriptionsItem>
        <DescriptionsItem :label="$t('lcm.page.certificate.lastSeenAt')">
          {{ formatDateTime(cert.lastSeenAt) }}
        </DescriptionsItem>
      </Descriptions>

      <Divider>{{ $t('lcm.page.certificate.technicalDetails') }}</Divider>

      <Descriptions :column="1" bordered size="small">
        <DescriptionsItem :label="$t('lcm.page.certificate.publicKeyAlgorithm')">
          {{ cert.publicKeyAlgorithm ?? '-' }}
        </DescriptionsItem>
        <DescriptionsItem :label="$t('lcm.page.certificate.publicKeySize')">
          {{ cert.publicKeySize ? `${cert.publicKeySize} bits` : '-' }}
        </DescriptionsItem>
        <DescriptionsItem :label="$t('lcm.page.certificate.signatureAlgorithm')">
          {{ cert.signatureAlgorithm ?? '-' }}
        </DescriptionsItem>
        <DescriptionsItem :label="$t('lcm.page.certificate.fingerprintSha256')">
          <Paragraph
            v-if="cert.fingerprintSha256"
            :copyable="{ text: cert.fingerprintSha256 }"
            style="margin-bottom: 0; font-family: monospace; font-size: 12px; word-break: break-all;"
          >
            {{ cert.fingerprintSha256 }}
          </Paragraph>
          <span v-else>-</span>
        </DescriptionsItem>
      </Descriptions>

      <template v-if="cert.dnsNames && cert.dnsNames.length > 0">
        <Divider>{{ $t('lcm.page.certificate.sans') }}</Divider>
        <Descriptions :column="1" bordered size="small">
          <DescriptionsItem :label="$t('lcm.page.certificate.dnsNames')">
            <div>
              <Tag v-for="name in cert.dnsNames" :key="name" style="margin: 2px;">
                {{ name }}
              </Tag>
            </div>
          </DescriptionsItem>
          <DescriptionsItem v-if="cert.ipAddresses?.length" :label="$t('lcm.page.certificate.ipAddresses')">
            <div>
              <Tag v-for="ip in cert.ipAddresses" :key="ip" style="margin: 2px;">
                {{ ip }}
              </Tag>
            </div>
          </DescriptionsItem>
        </Descriptions>
      </template>

      <template v-if="cert.status === 'MTLS_CERTIFICATE_STATUS_REVOKED'">
        <Divider>{{ $t('lcm.page.certificate.revocationInfo') }}</Divider>
        <Descriptions :column="1" bordered size="small">
          <DescriptionsItem :label="$t('lcm.page.certificate.revokedAt')">
            {{ formatDateTime(cert.revokedAt) }}
          </DescriptionsItem>
          <DescriptionsItem :label="$t('lcm.page.certificate.revocationReason')">
            {{ cert.revocationReason ?? '-' }}
          </DescriptionsItem>
          <DescriptionsItem v-if="cert.revocationNotes" :label="$t('lcm.page.certificate.revocationNotes')">
            {{ cert.revocationNotes }}
          </DescriptionsItem>
        </Descriptions>
      </template>
    </template>
  </Drawer>
</template>
