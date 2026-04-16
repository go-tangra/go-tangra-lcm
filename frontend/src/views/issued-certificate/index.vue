<script lang="ts" setup>
import type { VxeGridProps } from 'shell/adapter/vxe-table';

import { h, computed, ref } from 'vue';

import { Page, useVbenDrawer, type VbenFormProps } from 'shell/vben/common-ui';
import { LucideEye, LucideDownload, LucideKeyRound, LucideRefreshCw, LucidePencil, LucideUpload } from 'shell/vben/icons';

import { notification } from 'ant-design-vue';

import { useVbenVxeGrid } from 'shell/adapter/vxe-table';
import { type IssuedCertificateInfo } from '../../api/services';
import { $t } from 'shell/locales';
import { useLcmIssuedCertificateStore } from '../../stores/lcm-issued-certificate.state';
import { useLcmIssuerStore } from '../../stores/lcm-issuer.state';
import { downloadFile } from '../../utils';

import IssuedCertificateDrawer from './issued-certificate-drawer.vue';
import IssuedCertificateEditDrawer from './issued-certificate-edit-drawer.vue';
import IssuedCertificateDeployDrawer from './issued-certificate-deploy-drawer.vue';

const issuedCertStore = useLcmIssuedCertificateStore();
const issuerStore = useLcmIssuerStore();

const statusList = computed(() => [
  { value: 'ISSUED_CERTIFICATE_STATUS_PENDING', label: $t('lcm.enum.issuedCertStatus.pending') },
  { value: 'ISSUED_CERTIFICATE_STATUS_PROCESSING', label: $t('lcm.enum.issuedCertStatus.processing') },
  { value: 'ISSUED_CERTIFICATE_STATUS_ISSUED', label: $t('lcm.enum.issuedCertStatus.issued') },
  { value: 'ISSUED_CERTIFICATE_STATUS_FAILED', label: $t('lcm.enum.issuedCertStatus.failed') },
  { value: 'ISSUED_CERTIFICATE_STATUS_EXPIRED', label: $t('lcm.enum.issuedCertStatus.expired') },
  { value: 'ISSUED_CERTIFICATE_STATUS_REVOKED', label: $t('lcm.enum.issuedCertStatus.revoked') },
  { value: 'ISSUED_CERTIFICATE_STATUS_RENEWED', label: $t('lcm.enum.issuedCertStatus.renewed') },
]);

const autoRenewOptions = computed(() => [
  { value: 'true', label: $t('enum.enable.true') },
  { value: 'false', label: $t('enum.enable.false') },
]);

const issuerOptions = ref<Array<{ value: string; label: string }>>([]);

async function loadIssuers() {
  try {
    const resp = await issuerStore.listIssuers();
    issuerOptions.value = (resp.issuers ?? []).map((issuer) => ({
      value: issuer.name ?? '',
      label: issuer.name ?? '',
    }));
  } catch {
    // Ignore errors loading issuers
  }
}
loadIssuers();

function statusToColor(status: string | undefined) {
  switch (status) {
    case 'ISSUED_CERTIFICATE_STATUS_ISSUED':
      return '#52C41A'; // green
    case 'ISSUED_CERTIFICATE_STATUS_PENDING':
      return '#FAAD14'; // orange
    case 'ISSUED_CERTIFICATE_STATUS_PROCESSING':
      return '#1890FF'; // blue
    case 'ISSUED_CERTIFICATE_STATUS_FAILED':
      return '#FF4D4F'; // red
    case 'ISSUED_CERTIFICATE_STATUS_EXPIRED':
      return '#FF4D4F'; // red
    case 'ISSUED_CERTIFICATE_STATUS_REVOKED':
      return '#8C8C8C'; // gray
    case 'ISSUED_CERTIFICATE_STATUS_RENEWED':
      return '#722ED1'; // purple
    default:
      return '#C9CDD4';
  }
}

function statusToName(status: string | undefined) {
  const item = statusList.value.find((s) => s.value === status);
  return item?.label ?? status ?? '';
}

function isIssued(row: IssuedCertificateInfo) {
  return row.status === 'ISSUED_CERTIFICATE_STATUS_ISSUED' ||
         row.status === 'ISSUED_CERTIFICATE_STATUS_RENEWED' ||
         row.status === 'ISSUED_CERTIFICATE_STATUS_EXPIRED';
}

function canRenew(row: IssuedCertificateInfo) {
  return row.status === 'ISSUED_CERTIFICATE_STATUS_ISSUED' ||
         row.status === 'ISSUED_CERTIFICATE_STATUS_EXPIRED';
}

const formOptions: VbenFormProps = {
  collapsed: false,
  showCollapseButton: false,
  submitOnEnter: true,
  schema: [
    {
      component: 'Select',
      fieldName: 'issuerName',
      label: $t('lcm.page.issuedCertificate.issuerName'),
      componentProps: {
        options: issuerOptions,
        placeholder: $t('ui.placeholder.select'),
        allowClear: true,
        showSearch: true,
        filterOption: (input: string, option: { label: string }) =>
          option.label.toLowerCase().includes(input.toLowerCase()),
      },
    },
    {
      component: 'Select',
      fieldName: 'status',
      label: $t('ui.table.status'),
      componentProps: {
        options: statusList,
        placeholder: $t('ui.placeholder.select'),
        allowClear: true,
      },
    },
    {
      component: 'Select',
      fieldName: 'autoRenewEnabled',
      label: $t('lcm.page.issuedCertificate.autoRenew'),
      componentProps: {
        options: autoRenewOptions,
        placeholder: $t('ui.placeholder.select'),
        allowClear: true,
      },
    },
  ],
};

const gridOptions: VxeGridProps<IssuedCertificateInfo> = {
  height: 'auto',
  stripe: false,
  toolbarConfig: {
    custom: true,
    export: true,
    import: false,
    refresh: true,
    zoom: true,
  },
  exportConfig: {},
  pagerConfig: {},
  rowConfig: {
    isHover: true,
  },

  proxyConfig: {
    ajax: {
      query: async ({ page }, formValues) => {
        return await issuedCertStore.listCertificates(
          {
            page: page.currentPage,
            pageSize: page.pageSize,
          },
          formValues,
        );
      },
    },
  },

  columns: [
    { title: $t('ui.table.seq'), type: 'seq', width: 50 },
    { title: 'ID', field: 'id', width: 280 },
    { title: $t('lcm.page.issuedCertificate.commonName'), field: 'commonName', minWidth: 180 },
    {
      title: $t('lcm.page.issuedCertificate.domains'),
      field: 'domains',
      minWidth: 200,
      slots: { default: 'domains' },
    },
    { title: $t('lcm.page.issuedCertificate.issuerName'), field: 'issuerName', width: 120 },
    {
      title: $t('ui.table.status'),
      field: 'status',
      slots: { default: 'status' },
      width: 110,
    },
    {
      title: $t('lcm.page.issuedCertificate.expiresAt'),
      field: 'expiresAt',
      formatter: 'formatDateTime',
      width: 160,
    },
    {
      title: $t('lcm.page.issuedCertificate.autoRenew'),
      field: 'autoRenewEnabled',
      slots: { default: 'autoRenew' },
      width: 110,
    },
    { title: $t('lcm.page.issuedCertificate.keyType'), field: 'keyType', width: 100 },
    {
      title: $t('ui.table.createdAt'),
      field: 'createdAt',
      formatter: 'formatDateTime',
      width: 160,
    },
    {
      title: $t('ui.table.action'),
      field: 'action',
      fixed: 'right',
      slots: { default: 'action' },
      width: 260,
    },
  ],
};

const [Grid, gridApi] = useVbenVxeGrid({ gridOptions, formOptions });

const [Drawer, drawerApi] = useVbenDrawer({
  connectedComponent: IssuedCertificateDrawer,

  onOpenChange(isOpen: boolean) {
    if (!isOpen) {
      gridApi.query();
    }
  },
});

const [EditDrawer, editDrawerApi] = useVbenDrawer({
  connectedComponent: IssuedCertificateEditDrawer,

  onOpenChange(isOpen: boolean) {
    if (!isOpen) {
      gridApi.query();
    }
  },
});

const [DeployDrawer, deployDrawerApi] = useVbenDrawer({
  connectedComponent: IssuedCertificateDeployDrawer,
});

function handleView(row: IssuedCertificateInfo) {
  drawerApi.setData({ row });
  drawerApi.open();
}

function handleEdit(row: IssuedCertificateInfo) {
  editDrawerApi.setData({ row });
  editDrawerApi.open();
}

function handleDeploy(row: IssuedCertificateInfo) {
  deployDrawerApi.setData({ row });
  deployDrawerApi.open();
}

async function handleDownloadCert(row: IssuedCertificateInfo) {
  if (!row.id) return;
  try {
    const resp = await issuedCertStore.getCertificate(row.id);
    if (!resp.certificatePem) {
      notification.error({ message: $t('lcm.page.issuedCertificate.noCertificate') });
      return;
    }
    downloadFile(resp.certificatePem, `${row.commonName ?? 'certificate'}.pem`);
    notification.success({ message: $t('lcm.page.issuedCertificate.downloadSuccess') });
  } catch {
    notification.error({ message: $t('lcm.page.issuedCertificate.downloadFailed') });
  }
}

async function handleForceRenew(row: IssuedCertificateInfo) {
  if (!row.id) return;
  try {
    await issuedCertStore.renewCertificate(row.id);
    notification.success({ message: $t('lcm.page.issuedCertificate.renewSuccess') });
    await gridApi.query();
  } catch {
    notification.error({ message: $t('lcm.page.issuedCertificate.renewFailed') });
  }
}

async function handleDownloadKey(row: IssuedCertificateInfo) {
  if (!row.id) return;
  try {
    const resp = await issuedCertStore.getCertificate(row.id, true);
    if (!resp.privateKeyPem) {
      notification.error({ message: $t('lcm.page.issuedCertificate.noPrivateKey') });
      return;
    }
    downloadFile(resp.privateKeyPem, `${row.commonName ?? 'private'}_key.pem`);
    notification.success({ message: $t('lcm.page.issuedCertificate.downloadSuccess') });
  } catch {
    notification.error({ message: $t('lcm.page.issuedCertificate.downloadFailed') });
  }
}
</script>

<template>
  <Page auto-content-height>
    <Grid :table-title="$t('lcm.menu.issuedCertificate')">
      <template #domains="{ row }">
        <span>{{ (row.domains ?? []).join(', ') }}</span>
      </template>
      <template #status="{ row }">
        <a-tag :color="statusToColor(row.status)">
          {{ statusToName(row.status) }}
        </a-tag>
      </template>
      <template #autoRenew="{ row }">
        <a-tag :color="row.autoRenewEnabled ? '#52C41A' : '#8C8C8C'">
          {{ row.autoRenewEnabled ? $t('enum.enable.true') : $t('enum.enable.false') }}
        </a-tag>
      </template>
      <template #action="{ row }">
        <a-button
          type="link"
          :icon="h(LucideEye)"
          :title="$t('ui.button.view')"
          @click.stop="handleView(row)"
        />
        <a-button
          type="link"
          :icon="h(LucidePencil)"
          :title="$t('ui.button.edit')"
          @click.stop="handleEdit(row)"
        />
        <a-button
          v-if="isIssued(row)"
          type="link"
          :icon="h(LucideUpload)"
          :title="$t('lcm.page.issuedCertificate.deploy')"
          @click.stop="handleDeploy(row)"
        />
        <a-button
          v-if="isIssued(row)"
          type="link"
          :icon="h(LucideDownload)"
          :title="$t('lcm.page.issuedCertificate.downloadCert')"
          @click.stop="handleDownloadCert(row)"
        />
        <a-button
          v-if="isIssued(row)"
          type="link"
          :icon="h(LucideKeyRound)"
          :title="$t('lcm.page.issuedCertificate.downloadKey')"
          @click.stop="handleDownloadKey(row)"
        />
        <a-popconfirm
          v-if="canRenew(row)"
          :cancel-text="$t('ui.button.cancel')"
          :ok-text="$t('ui.button.ok')"
          :title="$t('lcm.page.issuedCertificate.confirmForceRenew')"
          @confirm="handleForceRenew(row)"
        >
          <a-button
            type="link"
            :icon="h(LucideRefreshCw)"
            :title="$t('lcm.page.issuedCertificate.forceRenew')"
          />
        </a-popconfirm>
      </template>
    </Grid>
    <Drawer />
    <EditDrawer />
    <DeployDrawer />
  </Page>
</template>
