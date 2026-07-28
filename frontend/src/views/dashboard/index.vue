<script lang="ts" setup>
import { computed, onMounted, onUnmounted, ref } from 'vue';

import { Page } from 'shell/vben/common-ui';
import { $t } from 'shell/locales';

import {
  Card,
  Col,
  Empty,
  Progress,
  Row,
  Spin,
  Statistic,
  Tag,
} from 'ant-design-vue';

import {
  StatisticsService,
  type GetStatisticsResponse,
} from '../../api/services';
import { formatDateTime, formatTime } from '../../datetime';

// 30s auto-refresh matches the deployer dashboard cadence. Operators
// can hit Refresh for an immediate fetch when watching an in-progress
// renewal or rejection workflow.
const REFRESH_INTERVAL_MS = 30_000;

const stats = ref<GetStatisticsResponse | null>(null);
const loading = ref(true);
const lastUpdated = ref<Date | null>(null);
let refreshTimer: ReturnType<typeof setInterval> | undefined;

async function load() {
  loading.value = true;
  try {
    stats.value = await StatisticsService.getStatistics();
    lastUpdated.value = new Date();
  } catch {
    // Errors are logged server-side; surfacing transient blips on the
    // auto-refresh path would just create noise.
  } finally {
    loading.value = false;
  }
}

onMounted(() => {
  load();
  refreshTimer = setInterval(load, REFRESH_INTERVAL_MS);
});

onUnmounted(() => {
  if (refreshTimer) clearInterval(refreshTimer);
});

// String-encoded int64s from the API → display number.
const num = (v: string | number | undefined): number => Number(v ?? 0);

const issued = computed(() => stats.value?.issuedCertificates);
const mtls = computed(() => stats.value?.mtlsCertificates);
const clients = computed(() => stats.value?.clients);
const issuers = computed(() => stats.value?.issuers);
const recentErrors = computed(() => stats.value?.recentErrors ?? []);

const issuedTotal = computed(() => num(issued.value?.totalCount));

interface StatusSlice {
  key: string;
  label: string;
  value: number;
  color: string;
}

const issuedStatusSlices = computed<StatusSlice[]>(() => {
  const c = issued.value;
  if (!c) return [];
  return [
    { key: 'active', label: $t('lcm.page.dashboard.statusActive'), value: num(c.activeCount), color: '#52c41a' },
    { key: 'processing', label: $t('lcm.page.dashboard.statusProcessing'), value: num(c.processingCount), color: '#1677ff' },
    { key: 'pending', label: $t('lcm.page.dashboard.statusPending'), value: num(c.pendingCount), color: '#faad14' },
    { key: 'expired', label: $t('lcm.page.dashboard.statusExpired'), value: num(c.expiredCount), color: '#fa8c16' },
    { key: 'failed', label: $t('lcm.page.dashboard.statusFailed'), value: num(c.failedCount), color: '#ff4d4f' },
    { key: 'revoked', label: $t('lcm.page.dashboard.statusRevoked'), value: num(c.revokedCount), color: '#8c8c8c' },
  ].filter((s) => s.value > 0);
});

const issuerTypeEntries = computed<Array<[string, number]>>(() => {
  const m = issued.value?.byIssuerType ?? {};
  return Object.entries(m)
    .map(([k, v]) => [k, num(v)] as [string, number])
    .filter(([, v]) => v > 0)
    .sort((a, b) => b[1] - a[1]);
});

const issuerTypeMax = computed(() => {
  const entries = issuerTypeEntries.value;
  return entries.length === 0 ? 0 : Math.max(...entries.map(([, v]) => v));
});

const expiringSoon = computed(() => num(issued.value?.expireSoonCount));
const expiringSoonDays = computed(() => issued.value?.expireSoonDays ?? 30);
const autoRenew = computed(() => num(issued.value?.autoRenewEnabledCount));

const lastUpdatedLabel = computed(() => {
  if (!lastUpdated.value) return '';
  return formatTime(lastUpdated.value);
});
</script>

<template>
  <Page :title="$t('lcm.page.dashboard.title')" :description="$t('lcm.page.dashboard.description')">
    <template #extra>
      <span v-if="lastUpdatedLabel" class="text-xs text-gray-500 mr-3">
        {{ $t('lcm.page.dashboard.lastUpdated') }}: {{ lastUpdatedLabel }}
      </span>
      <a class="ant-btn ant-btn-default" @click="load">{{ $t('ui.button.refresh') }}</a>
    </template>

    <Spin :spinning="loading && !stats">
      <Empty
        v-if="!loading && !stats"
        :description="$t('lcm.page.dashboard.empty')"
        class="py-12"
      />

      <template v-if="stats">
        <!-- Top-level KPIs -->
        <Row :gutter="[16, 16]">
          <Col :xs="24" :sm="12" :md="6">
            <Card>
              <Statistic
                :title="$t('lcm.page.dashboard.issuedCertsTotal')"
                :value="issuedTotal"
              />
              <div class="text-xs text-gray-500 mt-1">
                {{ $t('lcm.page.dashboard.statusActive') }}:
                <b>{{ num(issued?.activeCount) }}</b>
              </div>
            </Card>
          </Col>

          <Col :xs="24" :sm="12" :md="6">
            <Card>
              <Statistic
                :title="$t('lcm.page.dashboard.expiringSoon', { days: expiringSoonDays })"
                :value="expiringSoon"
                :value-style="{ color: expiringSoon > 0 ? '#fa8c16' : '#52c41a' }"
              />
              <div class="text-xs text-gray-500 mt-1">
                {{ $t('lcm.page.dashboard.autoRenewEnabled') }}:
                <b>{{ autoRenew }}</b>
              </div>
            </Card>
          </Col>

          <Col :xs="24" :sm="12" :md="6">
            <Card>
              <Statistic
                :title="$t('lcm.page.dashboard.clientsTotal')"
                :value="num(clients?.totalCount)"
              />
              <div class="text-xs text-gray-500 mt-1">
                {{ $t('lcm.page.dashboard.statusActive') }}:
                <b>{{ num(clients?.activeCount) }}</b>
              </div>
            </Card>
          </Col>

          <Col :xs="24" :sm="12" :md="6">
            <Card>
              <Statistic
                :title="$t('lcm.page.dashboard.issuersTotal')"
                :value="num(issuers?.totalCount)"
              />
              <div class="text-xs text-gray-500 mt-1">
                <Tag color="success">{{ num(issuers?.activeCount) }} {{ $t('lcm.page.dashboard.statusActive') }}</Tag>
                <Tag v-if="num(issuers?.errorCount) > 0" color="error">{{ num(issuers?.errorCount) }} {{ $t('lcm.page.dashboard.statusError') }}</Tag>
              </div>
            </Card>
          </Col>
        </Row>

        <!-- Issued certs by status -->
        <Card class="mt-4" :title="$t('lcm.page.dashboard.issuedByStatus')">
          <div v-if="issuedStatusSlices.length === 0" class="text-gray-500 text-center py-6">
            {{ $t('lcm.page.dashboard.noCerts') }}
          </div>
          <div v-else class="flex flex-col gap-3">
            <div v-for="slice in issuedStatusSlices" :key="slice.key">
              <div class="flex justify-between text-sm mb-1">
                <span>{{ slice.label }}</span>
                <span>
                  <b>{{ slice.value }}</b>
                  <span class="text-gray-400 ml-1">
                    ({{ issuedTotal === 0 ? 0 : Math.round((slice.value / issuedTotal) * 100) }}%)
                  </span>
                </span>
              </div>
              <Progress
                :percent="issuedTotal === 0 ? 0 : (slice.value / issuedTotal) * 100"
                :show-info="false"
                :stroke-color="slice.color"
              />
            </div>
          </div>
        </Card>

        <!-- Issuer breakdown + mTLS overview -->
        <Row :gutter="[16, 16]" class="mt-4">
          <Col :xs="24" :md="12">
            <Card :title="$t('lcm.page.dashboard.certsByIssuerType')">
              <div v-if="issuerTypeEntries.length === 0" class="text-gray-500 text-center py-6">
                {{ $t('lcm.page.dashboard.noCerts') }}
              </div>
              <div v-else class="flex flex-col gap-3">
                <div v-for="[name, value] in issuerTypeEntries" :key="name">
                  <div class="flex justify-between text-sm mb-1">
                    <span>{{ name }}</span>
                    <span><b>{{ value }}</b></span>
                  </div>
                  <Progress
                    :percent="issuerTypeMax === 0 ? 0 : (value / issuerTypeMax) * 100"
                    :show-info="false"
                    stroke-color="#1677ff"
                  />
                </div>
              </div>
            </Card>
          </Col>

          <Col :xs="24" :md="12">
            <Card :title="$t('lcm.page.dashboard.mtlsOverview')">
              <Row :gutter="[12, 12]">
                <Col :span="12">
                  <Statistic :title="$t('lcm.page.dashboard.mtlsActive')" :value="num(mtls?.activeCount)" />
                </Col>
                <Col :span="12">
                  <Statistic :title="$t('lcm.page.dashboard.mtlsRevoked')" :value="num(mtls?.revokedCount)" />
                </Col>
                <Col :span="12">
                  <Statistic :title="$t('lcm.page.dashboard.mtlsClient')" :value="num(mtls?.byType?.clientCerts)" />
                </Col>
                <Col :span="12">
                  <Statistic :title="$t('lcm.page.dashboard.mtlsInternal')" :value="num(mtls?.byType?.internalCerts)" />
                </Col>
              </Row>
            </Card>
          </Col>
        </Row>

        <!-- Recent errors -->
        <Card class="mt-4" :title="$t('lcm.page.dashboard.recentErrors')">
          <div v-if="recentErrors.length === 0" class="text-gray-500 text-center py-6">
            {{ $t('lcm.page.dashboard.noErrors') }}
          </div>
          <ul v-else class="flex flex-col gap-2">
            <li
              v-for="e in recentErrors"
              :key="(e.jobId || e.commonName || '') + (e.occurredAt || '')"
              class="flex flex-col border-b pb-2"
            >
              <div class="flex justify-between text-sm">
                <span><b>{{ e.commonName || e.issuerName || e.jobId }}</b></span>
                <span class="text-gray-500">{{ e.occurredAt ? formatDateTime(e.occurredAt) : '' }}</span>
              </div>
              <div class="text-xs text-red-600 truncate">{{ e.errorMessage }}</div>
            </li>
          </ul>
        </Card>
      </template>
    </Spin>
  </Page>
</template>
