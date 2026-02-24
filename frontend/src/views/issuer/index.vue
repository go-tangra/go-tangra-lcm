<script lang="ts" setup>
import type { VxeGridProps } from 'shell/adapter/vxe-table';

import { h, computed, ref } from 'vue';

import { Page, useVbenDrawer, type VbenFormProps } from 'shell/vben/common-ui';
import { LucideEye, LucideTrash } from 'shell/vben/icons';

import { notification } from 'ant-design-vue';

import { useVbenVxeGrid } from 'shell/adapter/vxe-table';
import { type IssuerInfo } from '../../api/services';
import { $t } from 'shell/locales';
import { useLcmIssuerStore } from '../../stores/lcm-issuer.state';

import IssuerDrawer from './issuer-drawer.vue';

const issuerStore = useLcmIssuerStore();

const statusList = computed(() => [
  { value: 'ISSUER_STATUS_ACTIVE', label: $t('lcm.enum.issuerStatus.active') },
  { value: 'ISSUER_STATUS_DISABLED', label: $t('lcm.enum.issuerStatus.disabled') },
  { value: 'ISSUER_STATUS_ERROR', label: $t('lcm.enum.issuerStatus.error') },
]);

const typeList = computed(() => [
  { value: 'self', label: $t('lcm.enum.issuerType.self') },
  { value: 'acme', label: $t('lcm.enum.issuerType.acme') },
]);

function statusToColor(status: string | undefined) {
  switch (status) {
    case 'ISSUER_STATUS_ACTIVE':
      return '#52C41A'; // green
    case 'ISSUER_STATUS_DISABLED':
      return '#8C8C8C'; // gray
    case 'ISSUER_STATUS_ERROR':
      return '#FF4D4F'; // red
    default:
      return '#C9CDD4';
  }
}

function statusToName(status: string | undefined) {
  const item = statusList.value.find((s) => s.value === status);
  return item?.label ?? status ?? '';
}

function typeToName(type: string | undefined) {
  const item = typeList.value.find((t) => t.value === type);
  return item?.label ?? type ?? '';
}

const formOptions: VbenFormProps = {
  collapsed: false,
  showCollapseButton: false,
  submitOnEnter: true,
  schema: [
    {
      component: 'Select',
      fieldName: 'type',
      label: $t('lcm.page.issuer.type'),
      componentProps: {
        options: typeList,
        placeholder: $t('ui.placeholder.select'),
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

const gridOptions: VxeGridProps<IssuerInfo> = {
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
  rowConfig: {
    isHover: true,
  },

  proxyConfig: {
    ajax: {
      query: async () => {
        const resp = await issuerStore.listIssuers();
        // Client-side filtering could be added here if needed
        return {
          items: resp.issuers ?? [],
          total: resp.issuers?.length ?? 0,
        };
      },
    },
  },

  columns: [
    { title: $t('ui.table.seq'), type: 'seq', width: 50 },
    { title: $t('lcm.page.issuer.name'), field: 'name', minWidth: 150 },
    {
      title: $t('lcm.page.issuer.type'),
      field: 'type',
      slots: { default: 'type' },
      width: 100,
    },
    {
      title: $t('ui.table.status'),
      field: 'status',
      slots: { default: 'status' },
      width: 100,
    },
    { title: $t('ui.table.description'), field: 'description', minWidth: 200 },
    {
      title: $t('ui.table.createdAt'),
      field: 'createTime',
      formatter: 'formatDateTime',
      width: 160,
    },
    {
      title: $t('ui.table.updatedAt'),
      field: 'updateTime',
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

const drawerMode = ref<'create' | 'view'>('view');

const [Drawer, drawerApi] = useVbenDrawer({
  connectedComponent: IssuerDrawer,

  onOpenChange(isOpen: boolean) {
    if (!isOpen) {
      gridApi.query();
    }
  },
});

function openDrawer(row: IssuerInfo, mode: 'create' | 'view') {
  drawerMode.value = mode;
  drawerApi.setData({ row, mode });
  drawerApi.open();
}

/* View details */
function handleView(row: IssuerInfo) {
  openDrawer(row, 'view');
}

/* Create new issuer */
function handleCreate() {
  openDrawer({} as IssuerInfo, 'create');
}

/* Delete issuer */
async function handleDelete(row: IssuerInfo) {
  if (!row.name) {
    notification.error({ message: $t('lcm.page.issuer.error.noName') });
    return;
  }

  try {
    await issuerStore.deleteIssuer(row.name);
    notification.success({ message: $t('ui.notification.delete_success') });
    await gridApi.query();
  } catch {
    notification.error({ message: $t('ui.notification.delete_failed') });
  }
}
</script>

<template>
  <Page auto-content-height>
    <Grid :table-title="$t('lcm.menu.issuer')">
      <template #toolbar-tools>
        <a-button class="mr-2" type="primary" @click="handleCreate">
          {{ $t('ui.button.create', { moduleName: '' }) }}
        </a-button>
      </template>
      <template #type="{ row }">
        <a-tag color="blue">
          {{ typeToName(row.type) }}
        </a-tag>
      </template>
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
          :cancel-text="$t('ui.button.cancel')"
          :ok-text="$t('ui.button.ok')"
          :title="$t('ui.text.do_you_want_delete', { moduleName: row.name })"
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
