<script lang="ts" setup>
import { ref, computed } from 'vue';

import { useVbenDrawer } from 'shell/vben/common-ui';

defineOptions({
  name: 'PermissionDrawer',
});

import { Descriptions, DescriptionsItem, Tag, TypographyText } from 'ant-design-vue';

import { type CertificatePermission } from '../../api/services';
import { $t } from 'shell/locales';

const data = ref<{ row: CertificatePermission }>();

const title = computed(() => $t('lcm.page.certificatePermission.details'));

function permissionTypeToColor(type: string | undefined) {
  switch (type) {
    case 'PERMISSION_TYPE_FULL':
      return '#722ED1';
    case 'PERMISSION_TYPE_DOWNLOAD':
      return '#1890FF';
    case 'PERMISSION_TYPE_READ':
      return '#52C41A';
    default:
      return '#C9CDD4';
  }
}

function permissionTypeToName(type: string | undefined) {
  switch (type) {
    case 'PERMISSION_TYPE_FULL':
      return $t('lcm.enum.permissionType.full');
    case 'PERMISSION_TYPE_DOWNLOAD':
      return $t('lcm.enum.permissionType.download');
    case 'PERMISSION_TYPE_READ':
      return $t('lcm.enum.permissionType.read');
    default:
      return type ?? '';
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

function isExpired(expiresAt: string | undefined) {
  if (!expiresAt) return false;
  return new Date(expiresAt) < new Date();
}

const [Drawer, drawerApi] = useVbenDrawer({
  onCancel() {
    drawerApi.close();
  },

  onOpenChange(isOpen) {
    if (isOpen) {
      data.value = drawerApi.getData() as { row: CertificatePermission };
    }
  },
});

const permission = computed(() => data.value?.row);
</script>

<template>
  <Drawer :title="title" :footer="false">
    <template v-if="permission">
      <Descriptions :column="1" bordered size="small">
        <DescriptionsItem :label="$t('lcm.page.certificatePermission.certificateId')">
          <TypographyText code copyable>{{ permission.certificateId }}</TypographyText>
        </DescriptionsItem>
        <DescriptionsItem :label="$t('lcm.page.certificatePermission.granteeClientId')">
          {{ permission.granteeClientId }}
        </DescriptionsItem>
        <DescriptionsItem :label="$t('lcm.page.certificatePermission.granteeClientName')">
          {{ permission.granteeClientName ?? '-' }}
        </DescriptionsItem>
        <DescriptionsItem :label="$t('lcm.page.certificatePermission.permissionType')">
          <Tag :color="permissionTypeToColor(permission.permissionType)">
            {{ permissionTypeToName(permission.permissionType) }}
          </Tag>
        </DescriptionsItem>
        <DescriptionsItem :label="$t('lcm.page.certificatePermission.grantedBy')">
          {{ permission.grantedBy ?? '-' }}
        </DescriptionsItem>
        <DescriptionsItem :label="$t('lcm.page.certificatePermission.expiresAt')">
          <template v-if="!permission.expiresAt">
            <span>{{ $t('lcm.page.certificatePermission.noExpiration') }}</span>
          </template>
          <template v-else-if="isExpired(permission.expiresAt)">
            <Tag color="#FF4D4F">{{ $t('lcm.page.certificatePermission.expired') }}</Tag>
            <span style="margin-left: 8px;">{{ formatDateTime(permission.expiresAt) }}</span>
          </template>
          <template v-else>
            {{ formatDateTime(permission.expiresAt) }}
          </template>
        </DescriptionsItem>
        <DescriptionsItem :label="$t('ui.table.createTime')">
          {{ formatDateTime(permission.createdAt) }}
        </DescriptionsItem>
        <DescriptionsItem v-if="permission.updatedAt" :label="$t('ui.table.updateTime')">
          {{ formatDateTime(permission.updatedAt) }}
        </DescriptionsItem>
      </Descriptions>
    </template>
  </Drawer>
</template>
