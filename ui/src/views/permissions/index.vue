<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useCertificates } from '@/stores/certificates'
import { useIssuers } from '@/stores/issuers'
import PermissionDrawer from '@/components/PermissionDrawer.vue'
import type { ResourceType } from '@/api/types'

const certificates = useCertificates()
const issuers = useIssuers()
const drawer = ref(false)
const target = ref<{ type: ResourceType; id: string; name: string } | null>(null)

onMounted(async () => {
  await Promise.all([certificates.list(), issuers.list()])
})

function open(type: ResourceType, id: string, name: string): void {
  target.value = { type, id, name }
  drawer.value = true
}
</script>

<template>
  <div>
    <h1 class="text-h5 mb-4">Permissions</h1>
    <v-row>
      <v-col cols="12" md="6">
        <v-card title="Certificates" data-test="perm-certificates">
          <v-list density="compact">
            <v-list-item v-for="c in certificates.items" :key="c.id" :title="c.spiffe_id" :subtitle="c.serial ?? ''" :data-test="'perm-certificate-' + c.id" @click="open('certificate', c.id, c.spiffe_id)">
              <template #append><v-icon icon="mdi-shield-account-outline" size="small" /></template>
            </v-list-item>
            <v-list-item v-if="!certificates.items.length" title="No certificates." />
          </v-list>
        </v-card>
      </v-col>
      <v-col cols="12" md="6">
        <v-card title="Issuers" data-test="perm-issuers">
          <v-list density="compact">
            <v-list-item v-for="i in issuers.items" :key="i.id" :title="i.name" :subtitle="i.trust_domain" :data-test="'perm-issuer-' + i.id" @click="open('issuer', i.id, i.name)">
              <template #append><v-icon icon="mdi-shield-account-outline" size="small" /></template>
            </v-list-item>
            <v-list-item v-if="!issuers.items.length" title="No issuers." />
          </v-list>
        </v-card>
      </v-col>
    </v-row>
    <PermissionDrawer v-if="target" v-model="drawer" :resource-type="target.type" :resource-id="target.id" :resource-name="target.name" />
  </div>
</template>
