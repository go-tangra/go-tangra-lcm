<script lang="ts" setup>
import { ref, computed } from 'vue';

import { useVbenDrawer, useVbenForm } from 'shell/vben/common-ui';

import { Descriptions, DescriptionsItem, Tag, Divider, Typography, notification, Spin, Modal, Button } from 'ant-design-vue';

import {
  type CertificateJobInfo,
  type GetJobStatusResponse,
  type GetJobResultResponse,
} from '../../api/services';
import { $t } from 'shell/locales';
import { useLcmCertificateJobStore } from '../../stores/lcm-certificate-job.state';
import { generateCsr, downloadFile } from '../../utils';

const { Paragraph, Text } = Typography;

const certificateJobStore = useLcmCertificateJobStore();

const data = ref<{
  row: CertificateJobInfo;
  mode: 'create' | 'view';
  issuerOptions: Array<{ value: string; label: string }>;
}>();

const jobDetails = ref<GetJobStatusResponse | null>(null);
const jobResult = ref<GetJobResultResponse | null>(null);
const loading = ref(false);
const generating = ref(false);
const generatedPrivateKey = ref<string | null>(null);
const showPrivateKeyModal = ref(false);

const title = computed(() => {
  if (data.value?.mode === 'create') {
    return $t('lcm.page.certificateJob.requestCertificate');
  }
  return $t('lcm.page.certificateJob.details');
});

const isCreateMode = computed(() => data.value?.mode === 'create');

function statusToColor(status: string | undefined) {
  switch (status) {
    case 'CERTIFICATE_JOB_STATUS_PENDING':
      return '#FAAD14';
    case 'CERTIFICATE_JOB_STATUS_PROCESSING':
      return '#1890FF';
    case 'CERTIFICATE_JOB_STATUS_COMPLETED':
      return '#52C41A';
    case 'CERTIFICATE_JOB_STATUS_FAILED':
      return '#FF4D4F';
    case 'CERTIFICATE_JOB_STATUS_CANCELLED':
      return '#8C8C8C';
    default:
      return '#C9CDD4';
  }
}

function statusToName(status: string | undefined) {
  switch (status) {
    case 'CERTIFICATE_JOB_STATUS_PENDING':
      return $t('lcm.enum.jobStatus.pending');
    case 'CERTIFICATE_JOB_STATUS_PROCESSING':
      return $t('lcm.enum.jobStatus.processing');
    case 'CERTIFICATE_JOB_STATUS_COMPLETED':
      return $t('lcm.enum.jobStatus.completed');
    case 'CERTIFICATE_JOB_STATUS_FAILED':
      return $t('lcm.enum.jobStatus.failed');
    case 'CERTIFICATE_JOB_STATUS_CANCELLED':
      return $t('lcm.enum.jobStatus.cancelled');
    default:
      return status ?? '';
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

// Form for creating new certificate request
const [Form, formApi] = useVbenForm({
  showDefaultActions: false,
  schema: [
    {
      component: 'Select',
      fieldName: 'issuerName',
      label: $t('lcm.page.certificateJob.issuerName'),
      rules: 'required',
      componentProps: {
        options: computed(() => data.value?.issuerOptions ?? []),
        placeholder: $t('ui.placeholder.select'),
        showSearch: true,
        filterOption: (input: string, option: { label: string }) =>
          option.label.toLowerCase().includes(input.toLowerCase()),
      },
    },
    {
      component: 'Input',
      fieldName: 'commonName',
      label: $t('lcm.page.certificateJob.commonName'),
      rules: 'required',
      componentProps: {
        placeholder: 'e.g., example.com',
      },
    },
    {
      component: 'Textarea',
      fieldName: 'dnsNames',
      label: $t('lcm.page.certificateJob.dnsNames'),
      componentProps: {
        placeholder: 'One domain per line\ne.g.:\nexample.com\nwww.example.com',
        rows: 4,
      },
    },
    {
      component: 'Textarea',
      fieldName: 'ipAddresses',
      label: $t('lcm.page.certificateJob.ipAddresses'),
      componentProps: {
        placeholder: 'One IP per line\ne.g.:\n192.168.1.1\n10.0.0.1',
        rows: 3,
      },
    },
    {
      component: 'RadioGroup',
      fieldName: 'keyGenLocation',
      label: $t('lcm.page.certificateJob.keyGenLocation'),
      defaultValue: 'server',
      componentProps: {
        options: [
          { value: 'server', label: $t('lcm.page.certificateJob.keyGenServer') },
          { value: 'client', label: $t('lcm.page.certificateJob.keyGenClient') },
        ],
      },
      help: $t('lcm.page.certificateJob.keyGenHelp'),
    },
    {
      component: 'Select',
      fieldName: 'keyType',
      label: $t('lcm.page.certificateJob.keyType'),
      componentProps: {
        options: [
          { value: 'RSA', label: 'RSA' },
          { value: 'ECDSA', label: 'ECDSA' },
        ],
        placeholder: $t('ui.placeholder.select'),
        allowClear: true,
      },
      dependencies: {
        triggerFields: ['keyGenLocation'],
        if(values: Record<string, any>) {
          // Only show ECDSA option when server generates the key
          return values.keyGenLocation !== 'client';
        },
        show: true,
      },
    },
    {
      component: 'Select',
      fieldName: 'keyTypeClient',
      label: $t('lcm.page.certificateJob.keyType'),
      defaultValue: 'RSA',
      componentProps: {
        options: [
          { value: 'RSA', label: 'RSA' },
        ],
        placeholder: $t('ui.placeholder.select'),
        disabled: true,
      },
      help: $t('lcm.page.certificateJob.keyTypeClientHelp'),
      dependencies: {
        triggerFields: ['keyGenLocation'],
        if(values: Record<string, any>) {
          return values.keyGenLocation === 'client';
        },
        show: true,
      },
    },
    {
      component: 'Select',
      fieldName: 'keySize',
      label: $t('lcm.page.certificateJob.keySize'),
      componentProps: {
        options: [
          { value: 2048, label: '2048 bits' },
          { value: 4096, label: '4096 bits' },
        ],
        placeholder: $t('ui.placeholder.select'),
        allowClear: true,
      },
    },
    {
      component: 'InputNumber',
      fieldName: 'validityDays',
      label: $t('lcm.page.certificateJob.validityDays'),
      componentProps: {
        placeholder: '90',
        min: 1,
        max: 825,
      },
    },
  ],
});

async function loadJobDetails(jobId: string) {
  loading.value = true;
  try {
    const [statusResp, resultResp] = await Promise.all([
      certificateJobStore.getJobStatus(jobId),
      // Request with includePrivateKey=true to get the private key if server-generated
      certificateJobStore.getJobResult(jobId, true).catch(() => null),
    ]);
    jobDetails.value = statusResp;
    jobResult.value = resultResp;
  } catch (error) {
    console.error('Failed to load job details:', error);
  } finally {
    loading.value = false;
  }
}

const [Drawer, drawerApi] = useVbenDrawer({
  onCancel() {
    drawerApi.close();
  },

  async onConfirm() {
    if (isCreateMode.value) {
      try {
        const values = await formApi.getValues();

        // Parse DNS names and IP addresses from textarea
        const dnsNames = values.dnsNames
          ? values.dnsNames.split('\n').map((s: string) => s.trim()).filter(Boolean)
          : undefined;
        const ipAddresses = values.ipAddresses
          ? values.ipAddresses.split('\n').map((s: string) => s.trim()).filter(Boolean)
          : undefined;

        let csrPem: string | undefined;
        const isClientGenerated = values.keyGenLocation === 'client';

        // Generate CSR client-side if requested
        if (isClientGenerated) {
          generating.value = true;
          try {
            notification.info({
              message: $t('lcm.page.certificateJob.generatingKey'),
              description: $t('lcm.page.certificateJob.generatingKeyDesc'),
            });

            const result = await generateCsr({
              commonName: values.commonName,
              dnsNames,
              ipAddresses,
              keyType: 'RSA',
              keySize: values.keySize || 2048,
            });

            csrPem = result.csrPem;
            generatedPrivateKey.value = result.privateKeyPem;

            // Show modal with private key
            showPrivateKeyModal.value = true;
          } catch (error: any) {
            notification.error({
              message: $t('lcm.page.certificateJob.keyGenFailed'),
              description: error?.message,
            });
            return;
          } finally {
            generating.value = false;
          }
        }

        await certificateJobStore.requestCertificate({
          issuerName: values.issuerName,
          commonName: values.commonName,
          dnsNames,
          ipAddresses,
          csrPem,
          keyType: isClientGenerated ? undefined : values.keyType,
          keySize: isClientGenerated ? undefined : values.keySize,
          validityDays: values.validityDays,
          metadata: undefined,
        });

        notification.success({ message: $t('lcm.page.certificateJob.requestSuccess') });

        // Don't close drawer immediately if we're showing the private key modal
        if (!isClientGenerated) {
          drawerApi.close();
        }
      } catch (error: any) {
        notification.error({
          message: $t('lcm.page.certificateJob.requestFailed'),
          description: error?.message,
        });
      }
    } else {
      drawerApi.close();
    }
  },

  onOpenChange(isOpen) {
    if (isOpen) {
      data.value = drawerApi.getData() as typeof data.value;
      jobDetails.value = null;
      jobResult.value = null;
      generatedPrivateKey.value = null;
      showPrivateKeyModal.value = false;

      if (!isCreateMode.value && data.value?.row?.jobId) {
        loadJobDetails(data.value.row.jobId);
      }

      if (isCreateMode.value) {
        formApi.resetForm();
      }
    }
  },
});

const job = computed(() => jobDetails.value ?? data.value?.row);

// Download the generated private key
async function downloadPrivateKey() {
  if (generatedPrivateKey.value) {
    const values = await formApi.getValues();
    const commonName = values.commonName || 'private';
    const filename = `${commonName.replace(/[^a-zA-Z0-9.-]/g, '_')}_key.pem`;
    downloadFile(generatedPrivateKey.value, filename);
  }
}

// Close modal and drawer after saving key
function closePrivateKeyModal() {
  showPrivateKeyModal.value = false;
  generatedPrivateKey.value = null;
  drawerApi.close();
}
</script>

<template>
  <Drawer :title="title" :footer="isCreateMode" :loading="generating">
    <template v-if="isCreateMode">
      <Spin :spinning="generating" :tip="$t('lcm.page.certificateJob.generatingKey')">
        <Form />
      </Spin>
    </template>
    <template v-else>
      <Spin :spinning="loading">
        <template v-if="job">
          <Descriptions :column="1" bordered size="small">
            <DescriptionsItem :label="$t('lcm.page.certificateJob.jobId')">
              <Text code copyable>{{ job.jobId }}</Text>
            </DescriptionsItem>
            <DescriptionsItem :label="$t('ui.table.status')">
              <Tag :color="statusToColor(job.status)">
                {{ statusToName(job.status) }}
              </Tag>
            </DescriptionsItem>
            <DescriptionsItem :label="$t('lcm.page.certificateJob.issuerName')">
              {{ job.issuerName ?? '-' }}
            </DescriptionsItem>
            <DescriptionsItem :label="$t('lcm.page.certificateJob.issuerType')">
              {{ job.issuerType ?? '-' }}
            </DescriptionsItem>
            <DescriptionsItem :label="$t('lcm.page.certificateJob.commonName')">
              {{ job.commonName ?? '-' }}
            </DescriptionsItem>
          </Descriptions>

          <template v-if="jobDetails?.dnsNames?.length">
            <Divider>{{ $t('lcm.page.certificateJob.sans') }}</Divider>
            <Descriptions :column="1" bordered size="small">
              <DescriptionsItem :label="$t('lcm.page.certificateJob.dnsNames')">
                <div>
                  <Tag v-for="name in jobDetails.dnsNames" :key="name" style="margin: 2px;">
                    {{ name }}
                  </Tag>
                </div>
              </DescriptionsItem>
              <DescriptionsItem v-if="jobDetails.ipAddresses?.length" :label="$t('lcm.page.certificateJob.ipAddresses')">
                <div>
                  <Tag v-for="ip in jobDetails.ipAddresses" :key="ip" style="margin: 2px;">
                    {{ ip }}
                  </Tag>
                </div>
              </DescriptionsItem>
            </Descriptions>
          </template>

          <Divider>{{ $t('lcm.page.certificateJob.timestamps') }}</Divider>
          <Descriptions :column="2" bordered size="small">
            <DescriptionsItem :label="$t('ui.table.createdAt')">
              {{ formatDateTime(job.createdAt as string) }}
            </DescriptionsItem>
            <DescriptionsItem :label="$t('lcm.page.certificateJob.completedAt')">
              {{ formatDateTime(job.completedAt as string) }}
            </DescriptionsItem>
          </Descriptions>

          <template v-if="job.status === 'CERTIFICATE_JOB_STATUS_FAILED' && job.errorMessage">
            <Divider>{{ $t('lcm.page.certificateJob.errorInfo') }}</Divider>
            <Descriptions :column="1" bordered size="small">
              <DescriptionsItem :label="$t('lcm.page.certificateJob.errorMessage')">
                <Text type="danger">{{ job.errorMessage }}</Text>
              </DescriptionsItem>
            </Descriptions>
          </template>

          <!-- Request Info (CSR, Key Type, etc.) -->
          <template v-if="jobResult">
            <Divider>{{ $t('lcm.page.certificateJob.requestInfo') }}</Divider>
            <Descriptions :column="2" bordered size="small">
              <DescriptionsItem :label="$t('lcm.page.certificateJob.keyType')">
                {{ jobResult.keyType ?? '-' }}
              </DescriptionsItem>
              <DescriptionsItem :label="$t('lcm.page.certificateJob.keySize')">
                {{ jobResult.keySize ? `${jobResult.keySize} bits` : '-' }}
              </DescriptionsItem>
            </Descriptions>

            <template v-if="jobResult.csrPem">
              <Descriptions :column="1" bordered size="small" style="margin-top: 8px;">
                <DescriptionsItem :label="$t('lcm.page.certificateJob.csrPem')">
                  <Paragraph
                    :copyable="{ text: jobResult.csrPem }"
                    style="margin-bottom: 0; font-family: monospace; font-size: 11px; max-height: 150px; overflow: auto;"
                  >
                    <pre style="margin: 0; white-space: pre-wrap; word-break: break-all;">{{ jobResult.csrPem }}</pre>
                  </Paragraph>
                </DescriptionsItem>
              </Descriptions>
            </template>
          </template>

          <template v-if="jobResult && job.status === 'CERTIFICATE_JOB_STATUS_COMPLETED'">
            <Divider>{{ $t('lcm.page.certificateJob.certificateInfo') }}</Divider>
            <Descriptions :column="1" bordered size="small">
              <DescriptionsItem :label="$t('lcm.page.certificateJob.serialNumber')">
                <Text code copyable v-if="jobResult.serialNumber">{{ jobResult.serialNumber }}</Text>
                <span v-else>-</span>
              </DescriptionsItem>
              <DescriptionsItem :label="$t('lcm.page.certificateJob.issuedAt')">
                {{ formatDateTime(jobResult.issuedAt as string) }}
              </DescriptionsItem>
              <DescriptionsItem :label="$t('lcm.page.certificateJob.expiresAt')">
                {{ formatDateTime(jobResult.expiresAt as string) }}
              </DescriptionsItem>
              <DescriptionsItem :label="$t('lcm.page.certificateJob.certificatePem')">
                <Paragraph
                  v-if="jobResult.certificatePem"
                  :copyable="{ text: jobResult.certificatePem }"
                  style="margin-bottom: 0; font-family: monospace; font-size: 11px; max-height: 200px; overflow: auto;"
                >
                  <pre style="margin: 0; white-space: pre-wrap; word-break: break-all;">{{ jobResult.certificatePem }}</pre>
                </Paragraph>
                <span v-else>-</span>
              </DescriptionsItem>
              <DescriptionsItem v-if="jobResult.caCertificatePem" :label="$t('lcm.page.certificateJob.caCertificatePem')">
                <Paragraph
                  :copyable="{ text: jobResult.caCertificatePem }"
                  style="margin-bottom: 0; font-family: monospace; font-size: 11px; max-height: 150px; overflow: auto;"
                >
                  <pre style="margin: 0; white-space: pre-wrap; word-break: break-all;">{{ jobResult.caCertificatePem }}</pre>
                </Paragraph>
              </DescriptionsItem>
              <DescriptionsItem v-if="jobResult.privateKeyPem" :label="$t('lcm.page.certificateJob.privateKeyPem')">
                <Paragraph
                  :copyable="{ text: jobResult.privateKeyPem }"
                  style="margin-bottom: 0; font-family: monospace; font-size: 11px; max-height: 150px; overflow: auto; background: #fff7e6;"
                >
                  <pre style="margin: 0; white-space: pre-wrap; word-break: break-all;">{{ jobResult.privateKeyPem }}</pre>
                </Paragraph>
              </DescriptionsItem>
            </Descriptions>
          </template>
        </template>
      </Spin>
    </template>
  </Drawer>

  <!-- Private Key Modal - shown after client-side key generation -->
  <Modal
    v-model:open="showPrivateKeyModal"
    :title="$t('lcm.page.certificateJob.privateKeyTitle')"
    :closable="false"
    :maskClosable="false"
    width="700px"
  >
    <div style="margin-bottom: 16px;">
      <Text type="warning" strong>
        {{ $t('lcm.page.certificateJob.privateKeyWarning') }}
      </Text>
    </div>
    <Paragraph
      v-if="generatedPrivateKey"
      :copyable="{ text: generatedPrivateKey }"
      style="margin-bottom: 0; font-family: monospace; font-size: 11px; background: #f5f5f5; padding: 12px; border-radius: 4px;"
    >
      <pre style="margin: 0; white-space: pre-wrap; word-break: break-all; max-height: 300px; overflow: auto;">{{ generatedPrivateKey }}</pre>
    </Paragraph>

    <template #footer>
      <Button type="primary" @click="downloadPrivateKey">
        {{ $t('lcm.page.certificateJob.downloadPrivateKey') }}
      </Button>
      <Button @click="closePrivateKeyModal">
        {{ $t('lcm.page.certificateJob.savedKey') }}
      </Button>
    </template>
  </Modal>
</template>
