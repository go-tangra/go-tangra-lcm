<script lang="ts" setup>
import type { VxeGridProps } from 'shell/adapter/vxe-table';

import { h, computed, ref } from 'vue';

import { Page, useVbenDrawer, type VbenFormProps } from 'shell/vben/common-ui';
import { LucideEye, LucideCheck, LucideX, LucideTrash } from 'shell/vben/icons';

import { notification, Modal, Input } from 'ant-design-vue';

import { useVbenVxeGrid } from 'shell/adapter/vxe-table';
// MtlsCertificateRequest type from store
import type { MtlsCertificateRequest } from '../../stores/lcm-mtls-certificate-request.state';
import { $t } from 'shell/locales';
import { useLcmMtlsCertificateRequestStore } from '../../stores/lcm-mtls-certificate-request.state';

import MtlsCertificateRequestDrawer from './mtls-certificate-request-drawer.vue';

const requestStore = useLcmMtlsCertificateRequestStore();

const statusList = computed(() => [
  { value: 'MTLS_CERTIFICATE_REQUEST_STATUS_PENDING', label: $t('lcm.enum.requestStatus.pending') },
  { value: 'MTLS_CERTIFICATE_REQUEST_STATUS_APPROVED', label: $t('lcm.enum.requestStatus.approved') },
  { value: 'MTLS_CERTIFICATE_REQUEST_STATUS_REJECTED', label: $t('lcm.enum.requestStatus.rejected') },
  { value: 'MTLS_CERTIFICATE_REQUEST_STATUS_ISSUED', label: $t('lcm.enum.requestStatus.issued') },
  { value: 'MTLS_CERTIFICATE_REQUEST_STATUS_CANCELLED', label: $t('lcm.enum.requestStatus.cancelled') },
]);

function statusToColor(status: string | undefined) {
  switch (status) {
    case 'MTLS_CERTIFICATE_REQUEST_STATUS_PENDING':
      return '#FAAD14'; // orange
    case 'MTLS_CERTIFICATE_REQUEST_STATUS_APPROVED':
      return '#1890FF'; // blue
    case 'MTLS_CERTIFICATE_REQUEST_STATUS_REJECTED':
      return '#FF4D4F'; // red
    case 'MTLS_CERTIFICATE_REQUEST_STATUS_ISSUED':
      return '#52C41A'; // green
    case 'MTLS_CERTIFICATE_REQUEST_STATUS_CANCELLED':
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
      fieldName: 'clientId',
      label: $t('lcm.page.certificateRequest.clientId'),
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
  ],
};

const gridOptions: VxeGridProps<MtlsCertificateRequest> = {
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
        return await requestStore.listRequests(
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
    { title: $t('lcm.page.certificateRequest.requestId'), field: 'requestId', width: 280 },
    { title: $t('lcm.page.certificateRequest.clientId'), field: 'clientId', width: 120 },
    { title: $t('lcm.page.certificateRequest.commonName'), field: 'commonName', minWidth: 180 },
    { title: $t('lcm.page.certificateRequest.issuerName'), field: 'issuerName', width: 120 },
    {
      title: $t('ui.table.status'),
      field: 'status',
      slots: { default: 'status' },
      width: 110,
    },
    {
      title: $t('ui.table.createdAt'),
      field: 'createTime',
      formatter: 'formatDateTime',
      width: 160,
    },
    {
      title: $t('ui.table.action'),
      field: 'action',
      fixed: 'right',
      slots: { default: 'action' },
      width: 160,
    },
  ],
};

const [Grid, gridApi] = useVbenVxeGrid({ gridOptions, formOptions });

const [Drawer, drawerApi] = useVbenDrawer({
  connectedComponent: MtlsCertificateRequestDrawer,

  onOpenChange(isOpen: boolean) {
    if (!isOpen) {
      gridApi.query();
    }
  },
});

function openDrawer(row: MtlsCertificateRequest) {
  drawerApi.setData({ row });
  drawerApi.open();
}

/* View details */
function handleView(row: MtlsCertificateRequest) {
  openDrawer(row);
}

/* Approve request */
async function handleApprove(row: MtlsCertificateRequest) {
  if (!row.id) {
    notification.error({ message: $t('lcm.page.certificateRequest.error.noId') });
    return;
  }

  try {
    await requestStore.approveRequest(row.id);
    notification.success({ message: $t('lcm.page.certificateRequest.approveSuccess') });
    await gridApi.query();
  } catch (error: any) {
    notification.error({
      message: $t('lcm.page.certificateRequest.approveFailed'),
      description: error?.message,
    });
  }
}

/* Reject request */
const rejectReason = ref('');

function handleReject(row: MtlsCertificateRequest) {
  if (!row.id) {
    notification.error({ message: $t('lcm.page.certificateRequest.error.noId') });
    return;
  }

  rejectReason.value = '';

  Modal.confirm({
    title: $t('lcm.page.certificateRequest.rejectTitle'),
    content: h('div', {}, [
      h('p', {}, $t('lcm.page.certificateRequest.rejectPrompt')),
      h(Input.TextArea, {
        rows: 3,
        placeholder: $t('lcm.page.certificateRequest.rejectReasonPlaceholder'),
        value: rejectReason.value,
        'onUpdate:value': (val: string) => {
          rejectReason.value = val;
        },
      }),
    ]),
    okText: $t('ui.button.ok'),
    cancelText: $t('ui.button.cancel'),
    onOk: async () => {
      if (!rejectReason.value.trim()) {
        notification.error({ message: $t('lcm.page.certificateRequest.error.rejectReasonRequired') });
        return Promise.reject();
      }

      try {
        await requestStore.rejectRequest(row.id!, rejectReason.value);
        notification.success({ message: $t('lcm.page.certificateRequest.rejectSuccess') });
        await gridApi.query();
      } catch (error: any) {
        notification.error({
          message: $t('lcm.page.certificateRequest.rejectFailed'),
          description: error?.message,
        });
        return Promise.reject();
      }
    },
  });
}

/* Delete request */
async function handleDelete(row: MtlsCertificateRequest) {
  if (!row.id) {
    notification.error({ message: $t('lcm.page.certificateRequest.error.noId') });
    return;
  }

  try {
    await requestStore.deleteRequest(row.id);
    notification.success({ message: $t('ui.notification.delete_success') });
    await gridApi.query();
  } catch {
    notification.error({ message: $t('ui.notification.delete_failed') });
  }
}

function isPending(row: MtlsCertificateRequest) {
  return row.status === 'MTLS_CERTIFICATE_REQUEST_STATUS_PENDING';
}
</script>

<template>
  <Page auto-content-height>
    <Grid :table-title="$t('lcm.menu.mtlsCertificateRequest')">
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
        <a-popconfirm
          v-if="isPending(row)"
          :cancel-text="$t('ui.button.cancel')"
          :ok-text="$t('ui.button.ok')"
          :title="$t('lcm.page.certificateRequest.confirmApprove')"
          @confirm="handleApprove(row)"
        >
          <a-button
            type="link"
            :icon="h(LucideCheck)"
            :title="$t('lcm.page.certificateRequest.approve')"
            style="color: #52C41A;"
          />
        </a-popconfirm>
        <a-button
          v-if="isPending(row)"
          type="link"
          :icon="h(LucideX)"
          :title="$t('lcm.page.certificateRequest.reject')"
          style="color: #FF4D4F;"
          @click.stop="handleReject(row)"
        />
        <a-popconfirm
          :cancel-text="$t('ui.button.cancel')"
          :ok-text="$t('ui.button.ok')"
          :title="$t('ui.text.do_you_want_delete', { moduleName: row.requestId })"
          @confirm="handleDelete(row)"
        >
          <a-button
            danger
            type="link"
            :icon="h(LucideTrash)"
            :title="$t('ui.button.delete', { moduleName: '' })"
          />
        </a-popconfirm>
      </template>
    </Grid>
    <Drawer />
  </Page>
</template>
