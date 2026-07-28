<script lang="ts" setup>
import { ref, computed } from 'vue';

import { useVbenDrawer } from 'shell/vben/common-ui';

import { Descriptions, DescriptionsItem, Tag, Divider, Typography } from 'ant-design-vue';

import { type TenantSecret } from '../../api/services';
import { $t } from 'shell/locales';
import { formatDateTime as formatDateTimeShared } from '../../datetime';

const { Text } = Typography;

const data = ref<{ row: TenantSecret }>();

const title = computed(() => $t('lcm.page.tenantSecret.moduleName'));

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
  switch (status) {
    case 'TENANT_SECRET_STATUS_ACTIVE':
      return $t('lcm.enum.issuerStatus.active');
    case 'TENANT_SECRET_STATUS_DISABLED':
      return $t('lcm.enum.issuerStatus.disabled');
    default:
      return status ?? '';
  }
}

function formatDateTime(value: string | undefined) {
  if (!value) return '-';
  try {
    return formatDateTimeShared(value);
  } catch {
    return value;
  }
}

const [Drawer, drawerApi] = useVbenDrawer({
  onCancel() {
    drawerApi.close();
  },

  onOpenChange(isOpen) {
    if (isOpen) {
      data.value = drawerApi.getData() as { row: TenantSecret };
    }
  },
});

const secret = computed(() => data.value?.row);
</script>

<template>
  <Drawer :title="title" :footer="false">
    <template v-if="secret">
      <Descriptions :column="1" bordered size="small">
        <DescriptionsItem :label="$t('ui.table.id')">
          <Text code>{{ secret.id }}</Text>
        </DescriptionsItem>
        <DescriptionsItem :label="$t('lcm.page.tenantSecret.tenantId')">
          {{ secret.tenantId ?? '-' }}
        </DescriptionsItem>
        <DescriptionsItem :label="$t('lcm.page.tenantSecret.description')">
          {{ secret.description ?? '-' }}
        </DescriptionsItem>
        <DescriptionsItem :label="$t('ui.table.status')">
          <Tag :color="statusToColor(secret.status)">
            {{ statusToName(secret.status) }}
          </Tag>
        </DescriptionsItem>
      </Descriptions>

      <Divider>{{ $t('ui.table.timestamps') }}</Divider>
      <Descriptions :column="2" bordered size="small">
        <DescriptionsItem :label="$t('ui.table.createdAt')">
          {{ formatDateTime(secret.createTime as string) }}
        </DescriptionsItem>
        <DescriptionsItem :label="$t('ui.table.updatedAt')">
          {{ formatDateTime(secret.updateTime as string) }}
        </DescriptionsItem>
        <DescriptionsItem :label="$t('lcm.page.tenantSecret.expiresAt')" :span="2">
          {{ formatDateTime(secret.expiresAt as string) }}
        </DescriptionsItem>
      </Descriptions>
    </template>
  </Drawer>
</template>
