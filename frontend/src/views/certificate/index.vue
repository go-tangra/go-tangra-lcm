<script lang="ts" setup>
import type { VxeGridProps } from 'shell/adapter/vxe-table';

import { h, computed } from 'vue';

import { Page, useVbenDrawer, type VbenFormProps } from 'shell/vben/common-ui';
import { LucideEye, LucideShieldX, LucideDownload } from 'shell/vben/icons';

import { notification } from 'ant-design-vue';

import { useVbenVxeGrid } from 'shell/adapter/vxe-table';
import { $t } from 'shell/locales';
import { useLcmCertificateStore, type MtlsCertificate } from '../../stores/lcm-certificate.state';

import CertificateDrawer from './certificate-drawer.vue';

const certificateStore = useLcmCertificateStore();

const statusList = computed(() => [
  { value: 'MTLS_CERTIFICATE_STATUS_ACTIVE', label: $t('lcm.enum.certificateStatus.active') },
  { value: 'MTLS_CERTIFICATE_STATUS_EXPIRED', label: $t('lcm.enum.certificateStatus.expired') },
  { value: 'MTLS_CERTIFICATE_STATUS_REVOKED', label: $t('lcm.enum.certificateStatus.revoked') },
  { value: 'MTLS_CERTIFICATE_STATUS_SUSPENDED', label: $t('lcm.enum.certificateStatus.suspended') },
]);

function statusToColor(status: string | undefined) {
  switch (status) {
    case 'MTLS_CERTIFICATE_STATUS_ACTIVE':
      return '#52C41A'; // green
    case 'MTLS_CERTIFICATE_STATUS_EXPIRED':
      return '#FAAD14'; // orange
    case 'MTLS_CERTIFICATE_STATUS_REVOKED':
      return '#FF4D4F'; // red
    case 'MTLS_CERTIFICATE_STATUS_SUSPENDED':
      return '#8C8C8C'; // gray
    default:
      return '#C9CDD4';
  }
}

function statusToName(status: string | undefined) {
  const item = statusList.value.find((s) => s.value === status);
  return item?.label ?? status ?? '';
}

const formOptions: VbenFormProps = {
  collapsed: false,
  showCollapseButton: false,
  submitOnEnter: true,
  schema: [
    {
      component: 'Input',
      fieldName: 'commonName',
      label: $t('lcm.page.certificate.commonName'),
      componentProps: {
        placeholder: $t('ui.placeholder.input'),
        allowClear: true,
      },
    },
    {
      component: 'Input',
      fieldName: 'clientId',
      label: $t('lcm.page.certificate.clientId'),
      componentProps: {
        placeholder: $t('ui.placeholder.input'),
        allowClear: true,
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
      component: 'Checkbox',
      fieldName: 'includeExpired',
      label: $t('lcm.page.certificate.includeExpired'),
      componentProps: {},
    },
    {
      component: 'Checkbox',
      fieldName: 'includeRevoked',
      label: $t('lcm.page.certificate.includeRevoked'),
      componentProps: {},
    },
  ],
};

const gridOptions: VxeGridProps<MtlsCertificate> = {
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
        return await certificateStore.listMtlsCertificates(
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
    { title: $t('lcm.page.certificate.serialNumber'), field: 'serialNumber', width: 150 },
    { title: $t('lcm.page.certificate.commonName'), field: 'commonName', minWidth: 180 },
    { title: $t('lcm.page.certificate.clientId'), field: 'clientId', width: 120 },
    { title: $t('lcm.page.certificate.issuerName'), field: 'issuerName', width: 120 },
    {
      title: $t('ui.table.status'),
      field: 'status',
      slots: { default: 'status' },
      width: 100,
    },
    {
      title: $t('lcm.page.certificate.notBefore'),
      field: 'notBefore',
      formatter: 'formatDateTime',
      width: 140,
    },
    {
      title: $t('lcm.page.certificate.notAfter'),
      field: 'notAfter',
      formatter: 'formatDateTime',
      width: 140,
    },
    {
      title: $t('ui.table.action'),
      field: 'action',
      fixed: 'right',
      slots: { default: 'action' },
      width: 130,
    },
  ],
};

const [Grid, gridApi] = useVbenVxeGrid({ gridOptions, formOptions });

const [Drawer, drawerApi] = useVbenDrawer({
  connectedComponent: CertificateDrawer,

  onOpenChange(isOpen: boolean) {
    if (!isOpen) {
      gridApi.query();
    }
  },
});

function openDrawer(row: MtlsCertificate) {
  drawerApi.setData({ row });
  drawerApi.open();
}

/* View details */
function handleView(row: MtlsCertificate) {
  openDrawer(row);
}

/* Download certificate */
async function handleDownload(row: MtlsCertificate) {
  if (!row.serialNumber) {
    notification.error({ message: $t('lcm.page.certificate.error.noSerialNumber') });
    return;
  }

  try {
    const resp = await certificateStore.downloadCertificate(
      String(row.serialNumber),
      true,
    );

    // Create download
    const blob = new Blob([resp.certificatePem ?? ''], { type: 'application/x-pem-file' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${row.commonName ?? 'certificate'}.pem`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);

    notification.success({ message: $t('lcm.page.certificate.downloadSuccess') });
  } catch {
    notification.error({ message: $t('lcm.page.certificate.downloadFailed') });
  }
}

/* Revoke certificate */
async function handleRevoke(row: MtlsCertificate) {
  if (!row.serialNumber) {
    notification.error({ message: $t('lcm.page.certificate.error.noSerialNumber') });
    return;
  }

  try {
    await certificateStore.revokeCertificate(
      String(row.serialNumber),
      'MTLS_CERT_REVOCATION_REASON_UNSPECIFIED',
    );

    notification.success({ message: $t('lcm.page.certificate.revokeSuccess') });
    await gridApi.query();
  } catch {
    notification.error({ message: $t('lcm.page.certificate.revokeFailed') });
  }
}

function isRevoked(row: MtlsCertificate) {
  return row.status === 'MTLS_CERTIFICATE_STATUS_REVOKED';
}
</script>

<template>
  <Page auto-content-height>
    <Grid :table-title="$t('lcm.menu.certificate')">
      <template #status="{ row }">
        <a-tag :color="statusToColor(row.status)">
          {{ statusToName(row.status) }}
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
          :icon="h(LucideDownload)"
          :title="$t('ui.button.download')"
          @click.stop="handleDownload(row)"
        />
        <a-popconfirm
          v-if="!isRevoked(row)"
          :cancel-text="$t('ui.button.cancel')"
          :ok-text="$t('ui.button.ok')"
          :title="$t('lcm.page.certificate.confirmRevoke')"
          @confirm="handleRevoke(row)"
        >
          <a-button
            danger
            type="link"
            :icon="h(LucideShieldX)"
            :title="$t('lcm.page.certificate.revoke')"
          />
        </a-popconfirm>
      </template>
    </Grid>
    <Drawer />
  </Page>
</template>
