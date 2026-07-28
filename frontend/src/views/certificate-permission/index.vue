<script lang="ts" setup>
import type { VxeGridProps } from 'shell/adapter/vxe-table';

import { h, computed } from 'vue';

import { Page, useVbenDrawer, type VbenFormProps } from 'shell/vben/common-ui';
import { LucideEye, LucideTrash2 } from 'shell/vben/icons';

import { notification } from 'ant-design-vue';

import { useVbenVxeGrid } from 'shell/adapter/vxe-table';
import { type CertificatePermission } from '../../api/services';
import { $t } from 'shell/locales';
import { formatDateTime as formatDateTimeShared } from '../../datetime';
import { useLcmCertificatePermissionStore } from '../../stores/lcm-certificate-permission.state';

import PermissionDrawer from './permission-drawer.vue';
import GrantPermissionDrawer from './grant-permission-drawer.vue';

const permissionStore = useLcmCertificatePermissionStore();

const permissionTypeList = computed(() => [
  { value: 'PERMISSION_TYPE_READ', label: $t('lcm.enum.permissionType.read') },
  { value: 'PERMISSION_TYPE_DOWNLOAD', label: $t('lcm.enum.permissionType.download') },
  { value: 'PERMISSION_TYPE_FULL', label: $t('lcm.enum.permissionType.full') },
]);

function permissionTypeToColor(type: string | undefined) {
  switch (type) {
    case 'PERMISSION_TYPE_FULL':
      return '#722ED1'; // purple
    case 'PERMISSION_TYPE_DOWNLOAD':
      return '#1890FF'; // blue
    case 'PERMISSION_TYPE_READ':
      return '#52C41A'; // green
    default:
      return '#C9CDD4';
  }
}

function permissionTypeToName(type: string | undefined) {
  const item = permissionTypeList.value.find((s) => s.value === type);
  return item?.label ?? type ?? '';
}

function formatDateTime(value: string | undefined) {
  if (!value) return '-';
  try {
    return formatDateTimeShared(value);
  } catch {
    return value;
  }
}

function isExpired(row: CertificatePermission) {
  if (!row.expiresAt) return false;
  return new Date(row.expiresAt) < new Date();
}

const formOptions: VbenFormProps = {
  collapsed: false,
  showCollapseButton: false,
  submitOnEnter: true,
  schema: [
    {
      component: 'Input',
      fieldName: 'certificateId',
      label: $t('lcm.page.certificatePermission.certificateId'),
      componentProps: {
        placeholder: $t('ui.placeholder.input'),
        allowClear: true,
      },
    },
    {
      component: 'Input',
      fieldName: 'granteeClientId',
      label: $t('lcm.page.certificatePermission.granteeClientId'),
      componentProps: {
        placeholder: $t('ui.placeholder.input'),
        allowClear: true,
      },
    },
    {
      component: 'Select',
      fieldName: 'permissionType',
      label: $t('lcm.page.certificatePermission.permissionType'),
      componentProps: {
        options: permissionTypeList,
        placeholder: $t('ui.placeholder.select'),
        allowClear: true,
      },
    },
    {
      component: 'Checkbox',
      fieldName: 'includeExpired',
      label: $t('lcm.page.certificatePermission.includeExpired'),
      componentProps: {},
    },
  ],
};

const gridOptions: VxeGridProps<CertificatePermission> = {
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
        return await permissionStore.listAllPermissions(
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
    { title: $t('lcm.page.certificatePermission.certificateId'), field: 'certificateId', minWidth: 200 },
    { title: $t('lcm.page.certificatePermission.granteeClientName'), field: 'granteeClientName', width: 150 },
    { title: $t('lcm.page.certificatePermission.grantedBy'), field: 'grantedBy', width: 120 },
    {
      title: $t('lcm.page.certificatePermission.permissionType'),
      field: 'permissionType',
      slots: { default: 'permissionType' },
      width: 120,
    },
    {
      title: $t('lcm.page.certificatePermission.expiresAt'),
      field: 'expiresAt',
      slots: { default: 'expiresAt' },
      width: 160,
    },
    {
      title: $t('ui.table.createTime'),
      field: 'createdAt',
      formatter: 'formatDateTime',
      width: 160,
    },
    {
      title: $t('ui.table.action'),
      field: 'action',
      fixed: 'right',
      slots: { default: 'action' },
      width: 100,
    },
  ],
};

const [Grid, gridApi] = useVbenVxeGrid({ gridOptions, formOptions });

const [Drawer, drawerApi] = useVbenDrawer({
  connectedComponent: PermissionDrawer,

  onOpenChange(isOpen: boolean) {
    if (!isOpen) {
      gridApi.query();
    }
  },
});

const [GrantDrawer, grantDrawerApi] = useVbenDrawer({
  connectedComponent: GrantPermissionDrawer,

  onOpenChange(isOpen: boolean) {
    if (!isOpen) {
      gridApi.query();
    }
  },
});

function openDrawer(row: CertificatePermission) {
  drawerApi.setData({ row });
  drawerApi.open();
}

function openGrantDrawer() {
  grantDrawerApi.open();
}

/* View details */
function handleView(row: CertificatePermission) {
  openDrawer(row);
}

/* Revoke permission */
async function handleRevoke(row: CertificatePermission) {
  if (!row.certificateId || !row.granteeClientId) {
    notification.error({ message: $t('lcm.page.certificatePermission.error.missingFields') });
    return;
  }

  try {
    await permissionStore.revokePermission(
      row.certificateId,
      String(row.granteeClientId),
    );

    notification.success({ message: $t('lcm.page.certificatePermission.revokeSuccess') });
    await gridApi.query();
  } catch {
    notification.error({ message: $t('lcm.page.certificatePermission.revokeFailed') });
  }
}
</script>

<template>
  <Page auto-content-height>
    <Grid :table-title="$t('lcm.menu.certificatePermission')">
      <template #toolbar-tools>
        <a-button type="primary" @click="openGrantDrawer">
          {{ $t('lcm.page.certificatePermission.grant') }}
        </a-button>
      </template>
      <template #permissionType="{ row }">
        <a-tag :color="permissionTypeToColor(row.permissionType)">
          {{ permissionTypeToName(row.permissionType) }}
        </a-tag>
      </template>
      <template #expiresAt="{ row }">
        <span v-if="!row.expiresAt">-</span>
        <a-tag v-else-if="isExpired(row)" color="#FF4D4F">
          {{ $t('lcm.page.certificatePermission.expired') }} ({{ formatDateTime(row.expiresAt) }})
        </a-tag>
        <span v-else>{{ formatDateTime(row.expiresAt) }}</span>
      </template>
      <template #action="{ row }">
        <a-button
          type="link"
          :icon="h(LucideEye)"
          :title="$t('ui.button.view')"
          @click.stop="handleView(row)"
        />
        <a-popconfirm
          :cancel-text="$t('ui.button.cancel')"
          :ok-text="$t('ui.button.ok')"
          :title="$t('lcm.page.certificatePermission.confirmRevoke')"
          @confirm="handleRevoke(row)"
        >
          <a-button
            danger
            type="link"
            :icon="h(LucideTrash2)"
            :title="$t('lcm.page.certificatePermission.revoke')"
          />
        </a-popconfirm>
      </template>
    </Grid>
    <Drawer />
    <GrantDrawer />
  </Page>
</template>
