<script lang="ts" setup>
import { ref, reactive, onMounted } from 'vue';

import { useVbenDrawer } from 'shell/vben/common-ui';

import {
  Form,
  FormItem,
  Select,
  notification,
  Descriptions,
  DescriptionsItem,
  Tag,
  Spin,
} from 'ant-design-vue';

import {
  type IssuedCertificateInfo,
  type DeploymentTargetInfo,
} from '../../api/services';
import { $t } from 'shell/locales';
import { useLcmIssuedCertificateStore } from '../../stores/lcm-issued-certificate.state';

const issuedCertStore = useLcmIssuedCertificateStore();

const data = ref<{ row: IssuedCertificateInfo }>();
const saving = ref(false);
const loadingTargets = ref(false);
const targets = ref<DeploymentTargetInfo[]>([]);

const formState = reactive({
  deploymentTargetId: undefined as string | undefined,
});

async function loadTargets() {
  loadingTargets.value = true;
  try {
    const resp = await issuedCertStore.listDeploymentTargets();
    targets.value = resp.targets ?? [];
  } catch {
    targets.value = [];
  } finally {
    loadingTargets.value = false;
  }
}

const [Drawer, drawerApi] = useVbenDrawer({
  onCancel() {
    drawerApi.close();
  },

  async onConfirm() {
    if (!data.value?.row?.id) return;

    if (!formState.deploymentTargetId) {
      notification.warning({
        message: $t('lcm.page.issuedCertificate.selectTarget'),
      });
      return;
    }

    saving.value = true;
    try {
      const resp = await issuedCertStore.deployCertificate(data.value.row.id, {
        deploymentTargetId: formState.deploymentTargetId,
      });
      notification.success({
        message: $t('lcm.page.issuedCertificate.deploySuccess'),
        description: resp.message,
      });
      drawerApi.close();
    } catch {
      notification.error({
        message: $t('lcm.page.issuedCertificate.deployFailed'),
      });
    } finally {
      saving.value = false;
    }
  },

  onOpenChange(isOpen) {
    if (isOpen) {
      data.value = drawerApi.getData() as typeof data.value;
      formState.deploymentTargetId = undefined;
      loadTargets();
    }
  },
});

const targetOptions = ref<Array<{ value: string; label: string }>>([]);

onMounted(() => {
  // Watch targets changes to build options
});

function getTargetOptions() {
  return targets.value.map((t) => ({
    value: t.id ?? '',
    label: `${t.name ?? ''} (${t.configurationCount ?? 0} configs)`,
  }));
}
</script>

<template>
  <Drawer
    :title="$t('lcm.page.issuedCertificate.deployTitle')"
    :confirm-loading="saving"
    :confirm-text="$t('lcm.page.issuedCertificate.deployButton')"
    :cancel-text="$t('ui.button.cancel')"
  >
    <template v-if="data?.row">
      <Descriptions :column="1" bordered size="small" style="margin-bottom: 24px;">
        <DescriptionsItem :label="$t('lcm.page.issuedCertificate.commonName')">
          {{ data.row.commonName ?? '-' }}
        </DescriptionsItem>
        <DescriptionsItem :label="$t('lcm.page.issuedCertificate.domains')">
          <Tag v-for="domain in (data.row.domains ?? [])" :key="domain" style="margin: 2px;">
            {{ domain }}
          </Tag>
        </DescriptionsItem>
        <DescriptionsItem :label="$t('lcm.page.issuedCertificate.issuerName')">
          {{ data.row.issuerName ?? '-' }}
        </DescriptionsItem>
      </Descriptions>

      <Spin :spinning="loadingTargets">
        <Form layout="vertical">
          <FormItem :label="$t('lcm.page.issuedCertificate.deploymentTarget')">
            <Select
              v-model:value="formState.deploymentTargetId"
              :options="getTargetOptions()"
              :placeholder="$t('lcm.page.issuedCertificate.selectTarget')"
              show-search
              :filter-option="(input: string, option: { label: string }) =>
                option.label.toLowerCase().includes(input.toLowerCase())"
            />
          </FormItem>
        </Form>
      </Spin>
    </template>
  </Drawer>
</template>
