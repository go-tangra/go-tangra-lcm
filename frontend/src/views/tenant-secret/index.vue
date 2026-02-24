<script lang="ts" setup>
import type { VxeGridProps } from 'shell/adapter/vxe-table';

import { h, computed, ref, reactive, onMounted } from 'vue';

import { Page, useVbenDrawer, type VbenFormProps } from 'shell/vben/common-ui';
import { LucideEye, LucideRefreshCw, LucideTrash, LucidePlus } from 'shell/vben/icons';

import { notification, Modal, Form, Input, Select, Checkbox } from 'ant-design-vue';

import { useVbenVxeGrid } from 'shell/adapter/vxe-table';
import { type TenantSecret } from '../../api/services';
import { $t } from 'shell/locales';
import { useLcmTenantSecretStore } from '../../stores/lcm-tenant-secret.state';
import { useTenantStore } from 'shell/stores';

import TenantSecretDrawer from './tenant-secret-drawer.vue';

const secretStore = useLcmTenantSecretStore();
const tenantStore = useTenantStore();

/* Tenant Options */
const tenantOptions = ref<Array<{ value: number; label: string }>>([]);
const tenantLoading = ref(false);

async function loadTenants() {
  try {
    tenantLoading.value = true;
    const result = await tenantStore.listTenant(
      { page: 1, pageSize: 100 },
      null,
      'id,name,code',
    );
    tenantOptions.value = (result.items ?? []).map((tenant: any) => ({
      value: tenant.id,
      label: `${tenant.name} (${tenant.code})`,
    }));
  } catch (error) {
    console.error('Failed to load tenants:', error);
  } finally {
    tenantLoading.value = false;
  }
}

onMounted(() => {
  loadTenants();
});

const statusList = computed(() => [
  { value: 'TENANT_SECRET_STATUS_ACTIVE', label: $t('lcm.enum.issuerStatus.active') },
  { value: 'TENANT_SECRET_STATUS_DISABLED', label: $t('lcm.enum.issuerStatus.disabled') },
]);

function statusToColor(status: string | undefined) {
  switch (status) {
    case 'TENANT_SECRET_STATUS_ACTIVE':
      return '#52C41A'; // green
    case 'TENANT_SECRET_STATUS_DISABLED':
      return '#8C8C8C'; // gray
    default:
      return '#C9CDD4';
  }
}

function statusToName(status: string | undefined) {
  const item = statusList.value.find((s) => s.value === status);
  return item?.label ?? status ?? '';
}

/* Create Modal State */
const createModalVisible = ref(false);
const createFormRef = ref();
const createLoading = ref(false);
const createFormState = reactive({
  tenantId: undefined as number | undefined,
  secret: '',
  description: '',
});

function handleCreate() {
  createFormState.tenantId = undefined;
  createFormState.secret = '';
  createFormState.description = '';
  createModalVisible.value = true;
}

async function handleCreateSubmit() {
  try {
    await createFormRef.value?.validate();
    createLoading.value = true;

    await secretStore.createTenantSecret({
      tenantId: createFormState.tenantId!,
      secret: createFormState.secret,
      description: createFormState.description || undefined,
    });

    notification.success({ message: $t('ui.notification.create_success') });
    createModalVisible.value = false;
    await gridApi.query();
  } catch (error: any) {
    if (error?.errorFields) {
      // Form validation error
      return;
    }
    notification.error({
      message: $t('ui.notification.create_failed'),
      description: error?.message,
    });
  } finally {
    createLoading.value = false;
  }
}

function handleCreateCancel() {
  createModalVisible.value = false;
}

const formOptions: VbenFormProps = {
  collapsed: false,
  showCollapseButton: false,
  submitOnEnter: true,
  schema: [
    {
      component: 'Select',
      fieldName: 'tenantId',
      label: $t('menu.tenant.member'),
      componentProps: {
        options: tenantOptions,
        placeholder: $t('ui.placeholder.select'),
        allowClear: true,
        showSearch: true,
        filterOption: (input: string, option: any) =>
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
  ],
};

const gridOptions: VxeGridProps<TenantSecret> = {
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
        return await secretStore.listTenantSecrets(
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
    { title: $t('lcm.page.tenantSecret.tenantId'), field: 'tenantId', width: 100 },
    { title: $t('lcm.page.tenantSecret.description'), field: 'description', minWidth: 200 },
    {
      title: $t('ui.table.status'),
      field: 'status',
      slots: { default: 'status' },
      width: 120,
    },
    {
      title: $t('lcm.page.tenantSecret.expiresAt'),
      field: 'expiresAt',
      formatter: 'formatDateTime',
      width: 160,
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
      width: 140,
    },
  ],
};

const [Grid, gridApi] = useVbenVxeGrid({ gridOptions, formOptions });

const [Drawer, drawerApi] = useVbenDrawer({
  connectedComponent: TenantSecretDrawer,

  onOpenChange(isOpen: boolean) {
    if (!isOpen) {
      gridApi.query();
    }
  },
});

function openDrawer(row: TenantSecret) {
  drawerApi.setData({ row });
  drawerApi.open();
}

/* View details */
function handleView(row: TenantSecret) {
  openDrawer(row);
}

/* Rotate secret state */
const rotateModalVisible = ref(false);
const rotateFormRef = ref();
const rotateLoading = ref(false);
const rotateFormState = reactive({
  id: 0,
  newSecret: '',
  disableOld: true,
});

function handleRotate(row: TenantSecret) {
  if (!row.id) {
    return;
  }
  rotateFormState.id = row.id;
  rotateFormState.newSecret = '';
  rotateFormState.disableOld = true;
  rotateModalVisible.value = true;
}

async function handleRotateSubmit() {
  try {
    await rotateFormRef.value?.validate();
    rotateLoading.value = true;

    await secretStore.rotateTenantSecret(
      rotateFormState.id,
      rotateFormState.newSecret,
      rotateFormState.disableOld,
    );
    notification.success({ message: $t('ui.notification.success') });
    rotateModalVisible.value = false;
    await gridApi.query();
  } catch (error: any) {
    if (error?.errorFields) {
      return;
    }
    notification.error({
      message: $t('ui.notification.failed'),
      description: error?.message,
    });
  } finally {
    rotateLoading.value = false;
  }
}

function handleRotateCancel() {
  rotateModalVisible.value = false;
}

/* Delete secret */
async function handleDelete(row: TenantSecret) {
  if (!row.id) {
    return;
  }

  try {
    await secretStore.deleteTenantSecret(row.id);
    notification.success({ message: $t('ui.notification.delete_success') });
    await gridApi.query();
  } catch {
    notification.error({ message: $t('ui.notification.delete_failed') });
  }
}
</script>

<template>
  <Page auto-content-height>
    <Grid :table-title="$t('lcm.menu.tenantSecret')">
      <template #toolbar-tools>
        <a-button class="mr-2" type="primary" @click="handleCreate">
          <template #icon><LucidePlus class="size-4" /></template>
          {{ $t('ui.button.create', { moduleName: '' }) }}
        </a-button>
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
        <a-button
          type="link"
          :icon="h(LucideRefreshCw)"
          :title="$t('lcm.page.tenantSecret.button.rotate')"
          style="color: #1890FF;"
          @click.stop="handleRotate(row)"
        />
        <a-popconfirm
          :cancel-text="$t('ui.button.cancel')"
          :ok-text="$t('ui.button.ok')"
          :title="$t('ui.text.do_you_want_delete', { moduleName: row.description || 'this secret' })"
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

    <!-- Create Tenant Secret Modal -->
    <Modal
      v-model:open="createModalVisible"
      :title="$t('ui.modal.create', { moduleName: $t('lcm.page.tenantSecret.moduleName') })"
      :confirm-loading="createLoading"
      @ok="handleCreateSubmit"
      @cancel="handleCreateCancel"
    >
      <Form
        ref="createFormRef"
        :model="createFormState"
        layout="vertical"
        class="mt-4"
      >
        <Form.Item
          :label="$t('menu.tenant.member')"
          name="tenantId"
          :rules="[{ required: true, message: $t('ui.placeholder.select') }]"
        >
          <Select
            v-model:value="createFormState.tenantId"
            :options="tenantOptions"
            :loading="tenantLoading"
            :placeholder="$t('ui.placeholder.select')"
            show-search
            :filter-option="(input: string, option: any) => option.label.toLowerCase().includes(input.toLowerCase())"
          />
        </Form.Item>
        <Form.Item
          :label="$t('lcm.page.tenantSecret.secret')"
          name="secret"
          :rules="[
            { required: true, message: $t('ui.placeholder.input') },
            { min: 16, message: $t('lcm.page.tenantSecret.secretMinLength') },
            { max: 256, message: $t('lcm.page.tenantSecret.secretMaxLength') },
          ]"
        >
          <Input.Password
            v-model:value="createFormState.secret"
            :placeholder="$t('lcm.page.tenantSecret.secretPlaceholder')"
          />
        </Form.Item>
        <Form.Item
          :label="$t('lcm.page.tenantSecret.description')"
          name="description"
        >
          <Input.TextArea
            v-model:value="createFormState.description"
            :placeholder="$t('ui.placeholder.input')"
            :rows="3"
          />
        </Form.Item>
      </Form>
    </Modal>

    <!-- Rotate Tenant Secret Modal -->
    <Modal
      v-model:open="rotateModalVisible"
      :title="$t('lcm.page.tenantSecret.button.rotate')"
      :confirm-loading="rotateLoading"
      @ok="handleRotateSubmit"
      @cancel="handleRotateCancel"
    >
      <Form
        ref="rotateFormRef"
        :model="rotateFormState"
        layout="vertical"
        class="mt-4"
      >
        <Form.Item
          :label="$t('lcm.page.tenantSecret.newSecret')"
          name="newSecret"
          :rules="[
            { required: true, message: $t('ui.placeholder.input') },
            { min: 16, message: $t('lcm.page.tenantSecret.secretMinLength') },
            { max: 256, message: $t('lcm.page.tenantSecret.secretMaxLength') },
          ]"
        >
          <Input.Password
            v-model:value="rotateFormState.newSecret"
            :placeholder="$t('lcm.page.tenantSecret.secretPlaceholder')"
          />
        </Form.Item>
        <Form.Item name="disableOld">
          <Checkbox v-model:checked="rotateFormState.disableOld">
            {{ $t('lcm.page.tenantSecret.disableOldSecret') }}
          </Checkbox>
        </Form.Item>
      </Form>
    </Modal>
  </Page>
</template>
