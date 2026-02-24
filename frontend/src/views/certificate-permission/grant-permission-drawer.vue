<script lang="ts" setup>
import { computed, ref } from 'vue';

import { useVbenDrawer, useVbenForm } from 'shell/vben/common-ui';

defineOptions({
  name: 'GrantPermissionDrawer',
});

import { notification } from 'ant-design-vue';

import { type PermissionType } from '../../api/services';
import { $t } from 'shell/locales';
import { useLcmCertificatePermissionStore } from '../../stores/lcm-certificate-permission.state';

const permissionStore = useLcmCertificatePermissionStore();

const title = computed(() => $t('lcm.page.certificatePermission.grantTitle'));

const loading = ref(false);

const permissionTypeOptions = computed(() => [
  { value: 'PERMISSION_TYPE_READ', label: $t('lcm.enum.permissionType.read') },
  { value: 'PERMISSION_TYPE_DOWNLOAD', label: $t('lcm.enum.permissionType.download') },
  { value: 'PERMISSION_TYPE_FULL', label: $t('lcm.enum.permissionType.full') },
]);

const [Form, formApi] = useVbenForm({
  schema: [
    {
      component: 'Input',
      fieldName: 'certificateId',
      label: $t('lcm.page.certificatePermission.certificateId'),
      rules: 'required',
      componentProps: {
        placeholder: $t('lcm.page.certificatePermission.certificateIdPlaceholder'),
      },
    },
    {
      component: 'Input',
      fieldName: 'granteeClientId',
      label: $t('lcm.page.certificatePermission.granteeClientId'),
      rules: 'required',
      componentProps: {
        placeholder: $t('lcm.page.certificatePermission.granteeClientIdPlaceholder'),
      },
    },
    {
      component: 'Select',
      fieldName: 'permissionType',
      label: $t('lcm.page.certificatePermission.permissionType'),
      rules: 'required',
      componentProps: {
        options: permissionTypeOptions,
        placeholder: $t('ui.placeholder.select'),
      },
      defaultValue: 'PERMISSION_TYPE_DOWNLOAD',
    },
    {
      component: 'DatePicker',
      fieldName: 'expiresAt',
      label: $t('lcm.page.certificatePermission.expiresAt'),
      componentProps: {
        placeholder: $t('lcm.page.certificatePermission.expiresAtPlaceholder'),
        showTime: true,
        format: 'YYYY-MM-DD HH:mm:ss',
      },
    },
  ],
  showDefaultActions: false,
});

const [Drawer, drawerApi] = useVbenDrawer({
  onCancel() {
    drawerApi.close();
  },

  async onConfirm() {
    const result = await formApi.validate();
    if (!result) return;

    const values = result as any;
    loading.value = true;
    try {
      await permissionStore.grantPermission(
        values.certificateId as string,
        values.granteeClientId as string,
        values.permissionType as PermissionType,
        values.expiresAt ? new Date(values.expiresAt).toISOString() : undefined,
      );

      notification.success({ message: $t('lcm.page.certificatePermission.grantSuccess') });
      formApi.resetForm();
      drawerApi.close();
    } catch {
      notification.error({ message: $t('lcm.page.certificatePermission.grantFailed') });
    } finally {
      loading.value = false;
    }
  },

  onOpenChange(isOpen) {
    if (!isOpen) {
      formApi.resetForm();
    }
  },
});
</script>

<template>
  <Drawer :title="title" :loading="loading">
    <Form />
  </Drawer>
</template>
