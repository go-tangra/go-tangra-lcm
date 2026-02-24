<script lang="ts" setup>
import { ref, computed, watch } from 'vue';

import { useVbenDrawer } from 'shell/vben/common-ui';

import {
  Descriptions,
  DescriptionsItem,
  Tag,
  Divider,
  Form,
  FormItem,
  Input,
  Select,
  InputNumber,
  Button,
  notification,
  Textarea,
  Collapse,
  CollapsePanel,
  AutoComplete,
} from 'ant-design-vue';

import {
  type IssuerInfo,
  type CreateIssuerRequest,
} from '../../api/services';
import { $t } from 'shell/locales';
import { useLcmIssuerStore } from '../../stores/lcm-issuer.state';

const issuerStore = useLcmIssuerStore();

const data = ref<{ row: IssuerInfo; mode: 'create' | 'view' }>();
const loading = ref(false);
const dnsProviders = ref<Array<{ name: string; description: string; requiredFields: string[]; optionalFields: string[] }>>([]);

// Form state for create mode
const formState = ref<{
  name: string;
  type: 'self-signed' | 'acme';
  keyType: 'ecdsa' | 'rsa';
  description: string;
  status: 'ISSUER_STATUS_ACTIVE' | 'ISSUER_STATUS_DISABLED';
  // Self-signed fields
  commonName: string;
  dnsNames: string;
  ipAddresses: string;
  caCommonName: string;
  caOrganization: string;
  caOrgUnit: string;
  caCountry: string;
  caProvince: string;
  caLocality: string;
  caValidityDays: number;
  // ACME fields
  acmeEmail: string;
  acmeEndpoint: string;
  acmeKeyType: 'rsa' | 'ec';
  acmeKeySize: number;
  challengeType: 'HTTP' | 'DNS';
  dnsProvider: string;
  maxRetries: number;
  baseDelay: string;
  eabKid: string;
  eabHmacKey: string;
  providerConfig: Record<string, string>;
}>({
  name: '',
  type: 'self-signed',
  keyType: 'ecdsa',
  description: '',
  status: 'ISSUER_STATUS_ACTIVE',
  commonName: '',
  dnsNames: '',
  ipAddresses: '',
  caCommonName: '',
  caOrganization: '',
  caOrgUnit: '',
  caCountry: '',
  caProvince: '',
  caLocality: '',
  caValidityDays: 365,
  acmeEmail: '',
  acmeEndpoint: 'https://acme-v02.api.letsencrypt.org/directory',
  acmeKeyType: 'ec',
  acmeKeySize: 2048,
  challengeType: 'HTTP',
  dnsProvider: '',
  maxRetries: 3,
  baseDelay: '2s',
  eabKid: '',
  eabHmacKey: '',
  providerConfig: {},
});

const title = computed(() => {
  if (data.value?.mode === 'create') {
    return $t('ui.modal.create', { moduleName: $t('lcm.page.issuer.moduleName') });
  }
  return $t('lcm.page.issuer.details');
});

function statusToColor(status: string | undefined) {
  switch (status) {
    case 'ISSUER_STATUS_ACTIVE':
      return '#52C41A';
    case 'ISSUER_STATUS_DISABLED':
      return '#8C8C8C';
    case 'ISSUER_STATUS_ERROR':
      return '#FF4D4F';
    default:
      return '#C9CDD4';
  }
}

function statusToName(status: string | undefined) {
  switch (status) {
    case 'ISSUER_STATUS_ACTIVE':
      return $t('lcm.enum.issuerStatus.active');
    case 'ISSUER_STATUS_DISABLED':
      return $t('lcm.enum.issuerStatus.disabled');
    case 'ISSUER_STATUS_ERROR':
      return $t('lcm.enum.issuerStatus.error');
    default:
      return status ?? '';
  }
}

function typeToName(type: string | undefined) {
  switch (type) {
    case 'self':
    case 'self-signed':
      return $t('lcm.enum.issuerType.self');
    case 'acme':
      return $t('lcm.enum.issuerType.acme');
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

async function loadDnsProviders() {
  try {
    const resp = await issuerStore.listDnsProviders();
    dnsProviders.value = (resp.providers ?? []).map((p) => ({
      name: p.name ?? '',
      description: p.description ?? '',
      requiredFields: p.requiredFields ?? [],
      optionalFields: p.optionalFields ?? [],
    }));
  } catch (e) {
    console.error('Failed to load DNS providers:', e);
  }
}

const selectedProviderInfo = computed(() => {
  return dnsProviders.value.find((p) => p.name === formState.value.dnsProvider);
});

// Watch for DNS provider changes to reset config
watch(
  () => formState.value.dnsProvider,
  () => {
    formState.value.providerConfig = {};
  },
);

async function handleSubmit() {
  loading.value = true;
  try {
    const request: CreateIssuerRequest = {
      name: formState.value.name,
      type: formState.value.type,
      keyType: formState.value.keyType,
      description: formState.value.description,
      status: formState.value.status,
    };

    if (formState.value.type === 'self-signed') {
      request.selfIssuer = {
        commonName: formState.value.commonName,
        dnsNames: formState.value.dnsNames
          .split(',')
          .map((s) => s.trim())
          .filter((s) => s),
        ipAddresses: formState.value.ipAddresses
          .split(',')
          .map((s) => s.trim())
          .filter((s) => s),
        caCommonName: formState.value.caCommonName,
        caOrganization: formState.value.caOrganization,
        caOrganizationalUnit: formState.value.caOrgUnit,
        caCountry: formState.value.caCountry,
        caProvince: formState.value.caProvince,
        caLocality: formState.value.caLocality,
        caValidityDays: formState.value.caValidityDays,
      };
    } else {
      request.acmeIssuer = {
        email: formState.value.acmeEmail,
        endpoint: formState.value.acmeEndpoint,
        keyType: formState.value.acmeKeyType,
        keySize: formState.value.acmeKeySize,
        challengeType: formState.value.challengeType,
        providerName: formState.value.dnsProvider,
        maxRetries: formState.value.maxRetries,
        baseDelay: formState.value.baseDelay,
        providerConfig: formState.value.providerConfig,
        eabKid: formState.value.eabKid || undefined,
        eabHmacKey: formState.value.eabHmacKey || undefined,
      };
    }

    await issuerStore.createIssuer(request);
    notification.success({ message: $t('ui.notification.create_success') });
    drawerApi.close();
  } catch (e) {
    console.error('Failed to create issuer:', e);
    notification.error({ message: $t('ui.notification.create_failed') });
  } finally {
    loading.value = false;
  }
}

function resetForm() {
  formState.value = {
    name: '',
    type: 'self-signed',
    keyType: 'ecdsa',
    description: '',
    status: 'ISSUER_STATUS_ACTIVE',
    commonName: '',
    dnsNames: '',
    ipAddresses: '',
    caCommonName: '',
    caOrganization: '',
    caOrgUnit: '',
    caCountry: '',
    caProvince: '',
    caLocality: '',
    caValidityDays: 365,
    acmeEmail: '',
    acmeEndpoint: 'https://acme-v02.api.letsencrypt.org/directory',
    acmeKeyType: 'ec',
    acmeKeySize: 2048,
    challengeType: 'HTTP',
    dnsProvider: '',
    maxRetries: 3,
    baseDelay: '2s',
    eabKid: '',
    eabHmacKey: '',
    providerConfig: {},
  };
}

const [Drawer, drawerApi] = useVbenDrawer({
  onCancel() {
    drawerApi.close();
  },

  async onOpenChange(isOpen) {
    if (isOpen) {
      data.value = drawerApi.getData() as {
        row: IssuerInfo;
        mode: 'create' | 'view';
      };
      if (data.value?.mode === 'create') {
        resetForm();
        await loadDnsProviders();
      }
    }
  },
});

const issuer = computed(() => data.value?.row);
const isViewMode = computed(() => data.value?.mode === 'view');
const isCreateMode = computed(() => data.value?.mode === 'create');
</script>

<template>
  <Drawer :title="title" :footer="false">
    <!-- View Mode -->
    <template v-if="issuer && isViewMode">
      <Descriptions :column="1" bordered size="small">
        <DescriptionsItem :label="$t('lcm.page.issuer.name')">
          {{ issuer.name }}
        </DescriptionsItem>
        <DescriptionsItem :label="$t('lcm.page.issuer.type')">
          <Tag color="blue">
            {{ typeToName(issuer.type) }}
          </Tag>
        </DescriptionsItem>
        <DescriptionsItem :label="$t('ui.table.status')">
          <Tag :color="statusToColor(issuer.status)">
            {{ statusToName(issuer.status) }}
          </Tag>
        </DescriptionsItem>
        <DescriptionsItem :label="$t('ui.table.description')">
          {{ issuer.description ?? '-' }}
        </DescriptionsItem>
      </Descriptions>

      <template v-if="issuer.config && Object.keys(issuer.config).length > 0">
        <Divider>{{ $t('lcm.page.issuer.config') }}</Divider>
        <Descriptions :column="1" bordered size="small">
          <DescriptionsItem
            v-for="(value, key) in issuer.config"
            :key="key"
            :label="key"
          >
            {{ value }}
          </DescriptionsItem>
        </Descriptions>
      </template>

      <Divider>{{ $t('lcm.page.issuer.timestamps') }}</Divider>
      <Descriptions :column="2" bordered size="small">
        <DescriptionsItem :label="$t('ui.table.createdAt')">
          {{ formatDateTime(issuer.createTime) }}
        </DescriptionsItem>
        <DescriptionsItem :label="$t('ui.table.updatedAt')">
          {{ formatDateTime(issuer.updateTime) }}
        </DescriptionsItem>
      </Descriptions>
    </template>

    <!-- Create Mode -->
    <template v-else-if="isCreateMode">
      <Form layout="vertical" :model="formState" @finish="handleSubmit">
        <!-- Basic Information -->
        <Divider orientation="left">{{
          $t('lcm.page.issuer.form.basicInfo')
        }}</Divider>

        <FormItem
          :label="$t('lcm.page.issuer.name')"
          name="name"
          :rules="[{ required: true, message: 'Name is required' }]"
        >
          <Input
            v-model:value="formState.name"
            placeholder="my-issuer"
            :maxlength="100"
          />
        </FormItem>

        <FormItem
          :label="$t('lcm.page.issuer.type')"
          name="type"
          :rules="[{ required: true }]"
        >
          <Select v-model:value="formState.type">
            <Select.Option value="self-signed">{{
              $t('lcm.enum.issuerType.self')
            }}</Select.Option>
            <Select.Option value="acme">{{
              $t('lcm.enum.issuerType.acme')
            }}</Select.Option>
          </Select>
        </FormItem>

        <FormItem :label="$t('lcm.page.issuer.keyType')" name="keyType">
          <Select v-model:value="formState.keyType">
            <Select.Option value="ecdsa">ECDSA</Select.Option>
            <Select.Option value="rsa">RSA</Select.Option>
          </Select>
        </FormItem>

        <FormItem :label="$t('ui.table.status')" name="status">
          <Select v-model:value="formState.status">
            <Select.Option value="ISSUER_STATUS_ACTIVE">{{
              $t('lcm.enum.issuerStatus.active')
            }}</Select.Option>
            <Select.Option value="ISSUER_STATUS_DISABLED">{{
              $t('lcm.enum.issuerStatus.disabled')
            }}</Select.Option>
          </Select>
        </FormItem>

        <FormItem :label="$t('ui.table.description')" name="description">
          <Textarea
            v-model:value="formState.description"
            :rows="2"
            :maxlength="500"
          />
        </FormItem>

        <!-- Self-Signed Configuration -->
        <template v-if="formState.type === 'self-signed'">
          <Divider orientation="left">{{
            $t('lcm.page.issuer.form.selfSignedConfig')
          }}</Divider>

          <FormItem
            :label="$t('lcm.page.issuer.form.commonName')"
            name="commonName"
            :rules="[{ required: true }]"
          >
            <Input
              v-model:value="formState.commonName"
              placeholder="example.com"
            />
          </FormItem>

          <FormItem :label="$t('lcm.page.issuer.form.dnsNames')" name="dnsNames">
            <Input
              v-model:value="formState.dnsNames"
              :placeholder="$t('lcm.page.issuer.form.dnsNamesHint')"
            />
          </FormItem>

          <FormItem
            :label="$t('lcm.page.issuer.form.ipAddresses')"
            name="ipAddresses"
          >
            <Input
              v-model:value="formState.ipAddresses"
              :placeholder="$t('lcm.page.issuer.form.ipAddressesHint')"
            />
          </FormItem>

          <Collapse>
            <CollapsePanel
              key="ca"
              :header="$t('lcm.page.issuer.form.caConfig')"
            >
              <FormItem
                :label="$t('lcm.page.issuer.form.caCommonName')"
                name="caCommonName"
                :rules="[{ required: true }]"
              >
                <Input
                  v-model:value="formState.caCommonName"
                  placeholder="My CA"
                />
              </FormItem>

              <FormItem
                :label="$t('lcm.page.issuer.form.caOrganization')"
                name="caOrganization"
              >
                <Input v-model:value="formState.caOrganization" />
              </FormItem>

              <FormItem
                :label="$t('lcm.page.issuer.form.caOrgUnit')"
                name="caOrgUnit"
              >
                <Input v-model:value="formState.caOrgUnit" />
              </FormItem>

              <FormItem
                :label="$t('lcm.page.issuer.form.caCountry')"
                name="caCountry"
              >
                <Input
                  v-model:value="formState.caCountry"
                  :maxlength="2"
                  placeholder="US"
                />
              </FormItem>

              <FormItem
                :label="$t('lcm.page.issuer.form.caProvince')"
                name="caProvince"
              >
                <Input v-model:value="formState.caProvince" />
              </FormItem>

              <FormItem
                :label="$t('lcm.page.issuer.form.caLocality')"
                name="caLocality"
              >
                <Input v-model:value="formState.caLocality" />
              </FormItem>

              <FormItem
                :label="$t('lcm.page.issuer.form.caValidityDays')"
                name="caValidityDays"
              >
                <InputNumber
                  v-model:value="formState.caValidityDays"
                  :min="30"
                  :max="3650"
                  style="width: 100%"
                />
              </FormItem>
            </CollapsePanel>
          </Collapse>
        </template>

        <!-- ACME Configuration -->
        <template v-if="formState.type === 'acme'">
          <Divider orientation="left">{{
            $t('lcm.page.issuer.form.acmeConfig')
          }}</Divider>

          <FormItem
            :label="$t('lcm.page.issuer.form.acmeEmail')"
            name="acmeEmail"
            :rules="[{ required: true, type: 'email' }]"
          >
            <Input
              v-model:value="formState.acmeEmail"
              placeholder="admin@example.com"
            />
          </FormItem>

          <FormItem
            :label="$t('lcm.page.issuer.form.acmeEndpoint')"
            name="acmeEndpoint"
            :rules="[{ required: true }]"
          >
            <AutoComplete
              v-model:value="formState.acmeEndpoint"
              :options="[
                { value: 'https://acme-v02.api.letsencrypt.org/directory', label: 'Let\'s Encrypt (Production)' },
                { value: 'https://acme-staging-v02.api.letsencrypt.org/directory', label: 'Let\'s Encrypt (Staging)' },
                { value: 'https://acme.zerossl.com/v2/DV90', label: 'ZeroSSL' },
              ]"
              placeholder="https://acme-v02.api.letsencrypt.org/directory"
            />
          </FormItem>

          <FormItem
            :label="$t('lcm.page.issuer.form.acmeKeyType')"
            name="acmeKeyType"
          >
            <Select v-model:value="formState.acmeKeyType">
              <Select.Option value="ec">EC (Elliptic Curve)</Select.Option>
              <Select.Option value="rsa">RSA</Select.Option>
            </Select>
          </FormItem>

          <FormItem
            :label="$t('lcm.page.issuer.form.acmeKeySize')"
            name="acmeKeySize"
          >
            <InputNumber
              v-model:value="formState.acmeKeySize"
              :min="2048"
              :max="4096"
              :step="1024"
              style="width: 100%"
            />
          </FormItem>

          <FormItem
            :label="$t('lcm.page.issuer.form.challengeType')"
            name="challengeType"
          >
            <Select v-model:value="formState.challengeType">
              <Select.Option value="HTTP">{{
                $t('lcm.page.issuer.form.challengeHttp')
              }}</Select.Option>
              <Select.Option value="DNS">{{
                $t('lcm.page.issuer.form.challengeDns')
              }}</Select.Option>
            </Select>
          </FormItem>

          <template v-if="formState.challengeType === 'DNS'">
            <FormItem
              :label="$t('lcm.page.issuer.form.dnsProvider')"
              name="dnsProvider"
              :rules="[{ required: true }]"
            >
              <Select
                v-model:value="formState.dnsProvider"
                :placeholder="$t('ui.placeholder.select')"
              >
                <Select.Option
                  v-for="provider in dnsProviders"
                  :key="provider.name"
                  :value="provider.name"
                >
                  {{ provider.name }} - {{ provider.description }}
                </Select.Option>
              </Select>
            </FormItem>

            <template v-if="selectedProviderInfo">
              <Divider orientation="left" :dashed="true">{{
                $t('lcm.page.issuer.form.dnsProviderConfig')
              }}</Divider>
              <FormItem
                v-for="field in selectedProviderInfo.requiredFields"
                :key="field"
                :label="field"
                :rules="[{ required: true }]"
              >
                <Input
                  :value="formState.providerConfig[field]"
                  @update:value="
                    (v: string) => (formState.providerConfig[field] = v)
                  "
                />
              </FormItem>
              <FormItem
                v-for="field in selectedProviderInfo.optionalFields"
                :key="field"
                :label="field"
              >
                <Input
                  :value="formState.providerConfig[field]"
                  @update:value="
                    (v: string) => (formState.providerConfig[field] = v)
                  "
                />
              </FormItem>
            </template>
          </template>

          <FormItem
            :label="$t('lcm.page.issuer.form.maxRetries')"
            name="maxRetries"
          >
            <InputNumber
              v-model:value="formState.maxRetries"
              :min="0"
              :max="100"
              style="width: 100%"
            />
          </FormItem>

          <FormItem
            :label="$t('lcm.page.issuer.form.baseDelay')"
            name="baseDelay"
          >
            <Input v-model:value="formState.baseDelay" placeholder="2s" />
          </FormItem>

          <Collapse>
            <CollapsePanel key="eab" :header="$t('lcm.page.issuer.form.eabHint')">
              <FormItem
                :label="$t('lcm.page.issuer.form.eabKid')"
                name="eabKid"
              >
                <Input v-model:value="formState.eabKid" />
              </FormItem>

              <FormItem
                :label="$t('lcm.page.issuer.form.eabHmacKey')"
                name="eabHmacKey"
              >
                <Input.Password v-model:value="formState.eabHmacKey" />
              </FormItem>
            </CollapsePanel>
          </Collapse>
        </template>

        <Divider />

        <FormItem>
          <Button type="primary" html-type="submit" :loading="loading" block>
            {{ $t('ui.button.create', { moduleName: '' }) }}
          </Button>
        </FormItem>
      </Form>
    </template>
  </Drawer>
</template>
