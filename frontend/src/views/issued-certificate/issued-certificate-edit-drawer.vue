<script lang="ts" setup>
import { ref, reactive } from 'vue';

import { useVbenDrawer } from 'shell/vben/common-ui';

import {
  Form,
  FormItem,
  Switch,
  InputNumber,
  notification,
  Descriptions,
  DescriptionsItem,
  Tag,
} from 'ant-design-vue';

import { type IssuedCertificateInfo } from '../../api/services';
import { $t } from 'shell/locales';
import { useLcmIssuedCertificateStore } from '../../stores/lcm-issued-certificate.state';

const issuedCertStore = useLcmIssuedCertificateStore();

const data = ref<{ row: IssuedCertificateInfo }>();
const saving = ref(false);

const formState = reactive({
  autoRenewEnabled: false,
  autoRenewDaysBeforeExpiry: 30,
});

const [Drawer, drawerApi] = useVbenDrawer({
  onCancel() {
    drawerApi.close();
  },

  async onConfirm() {
    if (!data.value?.row?.id) return;

    saving.value = true;
    try {
      await issuedCertStore.updateCertificate(data.value.row.id, {
        autoRenewEnabled: formState.autoRenewEnabled,
        autoRenewDaysBeforeExpiry: formState.autoRenewDaysBeforeExpiry,
      });
      notification.success({
        message: $t('lcm.page.issuedCertificate.updateSuccess'),
      });
      drawerApi.close();
    } catch {
      notification.error({
        message: $t('lcm.page.issuedCertificate.updateFailed'),
      });
    } finally {
      saving.value = false;
    }
  },

  onOpenChange(isOpen) {
    if (isOpen) {
      data.value = drawerApi.getData() as typeof data.value;
      const row = data.value?.row;
      if (row) {
        formState.autoRenewEnabled = row.autoRenewEnabled ?? false;
        formState.autoRenewDaysBeforeExpiry = row.autoRenewDaysBeforeExpiry ?? 30;
      }
    }
  },
});
</script>

<template>
  <Drawer
    :title="$t('lcm.page.issuedCertificate.editTitle')"
    :confirm-loading="saving"
    :confirm-text="$t('ui.button.save')"
    :cancel-text="$t('ui.button.cancel')"
  >
    <template v-if="data?.row">
      <Descriptions :column="1" bordered size="small" style="margin-bottom: 24px;">
        <DescriptionsItem :label="$t('lcm.page.issuedCertificate.commonName')">
          {{ data.row.commonName ?? '-' }}
        </DescriptionsItem>
        <DescriptionsItem :label="$t('lcm.page.issuedCertificate.issuerName')">
          {{ data.row.issuerName ?? '-' }}
        </DescriptionsItem>
        <DescriptionsItem :label="$t('ui.table.status')">
          <Tag :color="data.row.status === 'ISSUED_CERTIFICATE_STATUS_ISSUED' ? '#52C41A' : '#8C8C8C'">
            {{ data.row.status?.replace('ISSUED_CERTIFICATE_STATUS_', '') ?? '-' }}
          </Tag>
        </DescriptionsItem>
      </Descriptions>

      <Form layout="vertical">
        <FormItem :label="$t('lcm.page.issuedCertificate.autoRenew')">
          <Switch v-model:checked="formState.autoRenewEnabled" />
        </FormItem>
        <FormItem :label="$t('lcm.page.issuedCertificate.autoRenewDays')">
          <InputNumber
            v-model:value="formState.autoRenewDaysBeforeExpiry"
            :min="1"
            :max="90"
            :disabled="!formState.autoRenewEnabled"
            style="width: 100%;"
          />
        </FormItem>
      </Form>
    </template>
  </Drawer>
</template>
