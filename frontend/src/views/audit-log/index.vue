<script lang="ts" setup>
import type { VxeGridProps } from 'shell/adapter/vxe-table';

import { h, computed } from 'vue';

import { Page, useVbenDrawer, type VbenFormProps } from 'shell/vben/common-ui';
import { LucideEye } from 'shell/vben/icons';

import { useVbenVxeGrid } from 'shell/adapter/vxe-table';
import { $t } from 'shell/locales';

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
import { useLcmAuditLogStore } from '../../stores/lcm-audit-log.state';

import AuditLogDrawer from './audit-log-drawer.vue';

const auditLogStore = useLcmAuditLogStore();

const successStatusList = computed(() => [
  { value: true, label: $t('lcm.enum.successStatus.success') },
  { value: false, label: $t('lcm.enum.successStatus.failed') },
]);

function successToColor(success: boolean | undefined) {
  if (success === true) {
    return '#52C41A'; // green
  } else if (success === false) {
    return '#FF4D4F'; // red
  }
  return '#C9CDD4'; // gray
}

function successToName(success: boolean | undefined) {
  if (success === true) {
    return $t('lcm.enum.successStatus.success');
  } else if (success === false) {
    return $t('lcm.enum.successStatus.failed');
  }
  return '-';
}

const formOptions: VbenFormProps = {
  collapsed: false,
  showCollapseButton: false,
  submitOnEnter: true,
  schema: [
    {
      component: 'Input',
      fieldName: 'clientId',
      label: $t('lcm.page.auditLog.clientId'),
      componentProps: {
        placeholder: $t('ui.placeholder.input'),
        allowClear: true,
      },
    },
    {
      component: 'Input',
      fieldName: 'operation',
      label: $t('lcm.page.auditLog.operation'),
      componentProps: {
        placeholder: $t('ui.placeholder.input'),
        allowClear: true,
      },
    },
    {
      component: 'Select',
      fieldName: 'success',
      label: $t('lcm.page.auditLog.success'),
      componentProps: {
        options: successStatusList,
        placeholder: $t('ui.placeholder.select'),
        allowClear: true,
      },
    },
    {
      component: 'Input',
      fieldName: 'peerAddress',
      label: $t('lcm.page.auditLog.peerAddress'),
      componentProps: {
        placeholder: $t('ui.placeholder.input'),
        allowClear: true,
      },
    },
  ],
};

const gridOptions: VxeGridProps<AuditLog> = {
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
        return await auditLogStore.listAuditLogs(
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
    { title: $t('lcm.page.auditLog.auditId'), field: 'auditId', minWidth: 280 },
    { title: $t('lcm.page.auditLog.operation'), field: 'operation', minWidth: 180 },
    { title: $t('lcm.page.auditLog.clientId'), field: 'clientId', width: 120 },
    {
      title: $t('lcm.page.auditLog.success'),
      field: 'success',
      slots: { default: 'success' },
      width: 100,
    },
    { title: $t('lcm.page.auditLog.peerAddress'), field: 'peerAddress', width: 150 },
    { title: $t('lcm.page.auditLog.latencyMs'), field: 'latencyMs', width: 100 },
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
      width: 80,
    },
  ],
};

const [Grid, gridApi] = useVbenVxeGrid({ gridOptions, formOptions });

const [Drawer, drawerApi] = useVbenDrawer({
  connectedComponent: AuditLogDrawer,

  onOpenChange(isOpen: boolean) {
    if (!isOpen) {
      gridApi.query();
    }
  },
});

function openDrawer(row: AuditLog) {
  drawerApi.setData({ row });
  drawerApi.open();
}

/* View details */
function handleView(row: AuditLog) {
  openDrawer(row);
}
</script>

<template>
  <Page auto-content-height>
    <Grid :table-title="$t('lcm.menu.auditLog')">
      <template #success="{ row }">
        <a-tag :color="successToColor(row.success)">
          {{ successToName(row.success) }}
        </a-tag>
      </template>
      <template #action="{ row }">
        <a-button
          type="link"
          :icon="h(LucideEye)"
          :title="$t('ui.button.view')"
          @click.stop="handleView(row)"
        />
      </template>
    </Grid>
    <Drawer />
  </Page>
</template>
