<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useIssuers } from '@/stores/issuers'
import IssuerDrawer from '@/components/IssuerDrawer.vue'
import type { Issuer } from '@/api/types'

const store = useIssuers()
const drawer = ref(false)
const selected = ref<Issuer | null>(null)

onMounted(() => store.list())

function open(i: Issuer | null): void {
  selected.value = i
  drawer.value = true
}
</script>

<template>
  <div>
    <div class="d-flex align-center mb-4">
      <h1 class="text-h5">Issuers</h1>
      <v-spacer />
      <v-btn color="primary" prepend-icon="mdi-plus" data-test="issuer-new" @click="open(null)">New issuer</v-btn>
    </div>
    <v-alert v-if="store.error" type="error" variant="tonal" density="compact" class="mb-3">{{ store.error }}</v-alert>
    <v-table data-test="issuers-table">
      <thead>
        <tr><th>Name</th><th>Type</th><th>Trust domain</th><th>Default</th><th>Certificates</th></tr>
      </thead>
      <tbody>
        <tr v-for="i in store.items" :key="i.id" class="cursor-pointer" :data-test="'issuer-row-' + i.id" @click="open(i)">
          <td>{{ i.name }}</td>
          <td><v-chip size="x-small" variant="tonal">{{ i.type }}</v-chip></td>
          <td>{{ i.trust_domain }}</td>
          <td><v-icon v-if="i.is_default" icon="mdi-star" size="small" color="amber" /></td>
          <td>{{ i.certificate_count ?? 0 }}</td>
        </tr>
        <tr v-if="!store.items.length && !store.loading"><td colspan="5" class="text-medium-emphasis">No issuers yet.</td></tr>
      </tbody>
    </v-table>
    <IssuerDrawer v-model="drawer" :issuer="selected" @saved="store.list()" @removed="store.list()" />
  </div>
</template>

<style scoped>
.cursor-pointer { cursor: pointer; }
</style>
