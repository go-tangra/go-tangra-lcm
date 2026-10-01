<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import { UiPage, UiCard, UiDataTable, UiPermissionDrawer, usePermissionGrants, useListQuery, type Column } from '@go-tangra/ui'
import { PERM_CERTIFICATE_LIST, PERM_ISSUER_LIST, usePermCertificates, usePermIssuers, usePermissions } from '@/stores/permissions'
import { useDirectory } from '@/stores/directory'
import { grantable, type Certificate, type Issuer, type Relation, type ResourceType, type SubjectType } from '@/api/types'

const certificates = usePermCertificates()
const issuers = usePermIssuers()
const store = usePermissions()
const dir = useDirectory()
const drawer = ref(false)
const target = ref<{ type: ResourceType; id: string; name: string } | null>(null)

// Subjects, levels (never above the holder's own relation), grant/revoke handlers.
const perms = usePermissionGrants({
  grants: () => store.grants,
  effective: () => ({ relation: store.effective?.relation, canShare: store.effective?.permissions?.share ?? false }),
  grant: (r) => store.grant({ resource_type: target.value!.type, resource_id: target.value!.id, subject_type: r.subject_type as SubjectType, subject_id: r.subject_id, relation: r.relation as Relation, expires_at: r.expires_at }),
  revoke: (id) => store.revoke(id),
  directory: { roles: () => Object.values(dir.roles), searchUsers: dir.searchUsers, resolveUsers: dir.resolveUsers, userName: dir.userName, roleName: dir.roleName },
  grantable,
})
// --- server paging and sorting, one query per table ---
const cq = useListQuery('perm-certificates', PERM_CERTIFICATE_LIST.opts)
const iq = useListQuery('perm-issuers', PERM_ISSUER_LIST.opts)
async function loadCertificates(): Promise<void> {
  const res = await certificates.list({}, cq.query.value)
  if (res?.page) cq.clampTo(res.page)
}
async function loadIssuers(): Promise<void> {
  const res = await issuers.list({}, iq.query.value)
  if (res?.page) iq.clampTo(res.page)
}
watch(cq.query, () => void loadCertificates())
watch(iq.query, () => void loadIssuers())
onMounted(async () => {
  await Promise.all([loadCertificates(), loadIssuers(), dir.loadRoles()])
})
async function open(type: ResourceType, id: string, name: string): Promise<void> {
  target.value = { type, id, name }
  drawer.value = true
  await store.load(type, id)
  await perms.resolve()
}
const certColumns: Column<Certificate>[] = [{ key: 'identity', label: 'Identity', format: (c) => c.spiffe_id || (c.sans?.length ? c.sans.join(', ') : '') || c.subject || c.id, sortable: true }, { key: 'serial', label: 'Serial', hideOnStack: true }]
const issuerColumns: Column<Issuer>[] = [{ key: 'name', label: 'Name', sortable: true }, { key: 'trust_domain', label: 'Trust domain', hideOnStack: true, sortable: true }]
</script>

<template>
  <UiPage title="Permissions" subtitle="Who can read, edit, share or own each certificate and issuer">
    <div class="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <UiCard title="Certificates" :padded="false" data-test="perm-certificates">
        <UiDataTable :items="certificates.items" :columns="certColumns" :loading="certificates.loading" :total="certificates.total" :page="cq.page.value" :page-size="cq.pageSize.value" :sort="cq.sort.value" caption="Certificates" empty-title="No certificates" clickable :row-attrs="(c) => ({ 'data-test': 'perm-certificate-' + c.id })" @row-click="open('certificate', $event.id, $event.spiffe_id || $event.subject || $event.id)" @update:page="cq.setPage" @update:page-size="cq.setPageSize" @update:sort="cq.setSort" />
      </UiCard>
      <UiCard title="Issuers" :padded="false" data-test="perm-issuers">
        <UiDataTable :items="issuers.items" :columns="issuerColumns" :loading="issuers.loading" :total="issuers.total" :page="iq.page.value" :page-size="iq.pageSize.value" :sort="iq.sort.value" caption="Issuers" empty-title="No issuers" clickable :row-attrs="(i) => ({ 'data-test': 'perm-issuer-' + i.id })" @row-click="open('issuer', $event.id, $event.name)" @update:page="iq.setPage" @update:page-size="iq.setPageSize" @update:sort="iq.setSort" />
      </UiCard>
    </div>
    <UiPermissionDrawer v-model="drawer" :title="'Permissions — ' + (target?.name || target?.id || '')" :grants="perms.grants.value" :subjects="perms.subjects.value" :levels="perms.levels.value" :can-manage="perms.canShare.value" expires :editable-level="false" :hint="perms.hint.value" :error="perms.error.value" :busy="perms.busy.value" data-test="permission-drawer" @search="perms.search" @grant="perms.onGrant" @revoke="perms.onRevoke" @change-level="perms.onChangeLevel" />
  </UiPage>
</template>
