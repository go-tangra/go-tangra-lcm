<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { UiPage, UiCard, UiDataTable, UiPermissionDrawer, usePermissionGrants, type Column } from '@freya/ui'
import { useCertificates } from '@/stores/certificates'
import { useIssuers } from '@/stores/issuers'
import { usePermissions } from '@/stores/permissions'
import { useDirectory } from '@/stores/directory'
import { grantable, type Certificate, type Issuer, type Relation, type ResourceType, type SubjectType } from '@/api/types'

const certificates = useCertificates()
const issuers = useIssuers()
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
onMounted(async () => {
  await Promise.all([certificates.list(), issuers.list(), dir.loadRoles()])
})
async function open(type: ResourceType, id: string, name: string): Promise<void> {
  target.value = { type, id, name }
  drawer.value = true
  await store.load(type, id)
  await perms.resolve()
}
const certColumns: Column<Certificate>[] = [{ key: 'spiffe_id', label: 'Identity', format: (c) => c.spiffe_id || c.subject || c.id }, { key: 'serial', label: 'Serial', hideOnStack: true }]
const issuerColumns: Column<Issuer>[] = [{ key: 'name', label: 'Name' }, { key: 'trust_domain', label: 'Trust domain', hideOnStack: true }]
</script>

<template>
  <UiPage title="Permissions" subtitle="Who can read, edit, share or own each certificate and issuer">
    <div class="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <UiCard title="Certificates" :padded="false" data-test="perm-certificates">
        <UiDataTable :items="certificates.items" :columns="certColumns" caption="Certificates" empty-title="No certificates" clickable :row-attrs="(c) => ({ 'data-test': 'perm-certificate-' + c.id })" @row-click="open('certificate', $event.id, $event.spiffe_id)" />
      </UiCard>
      <UiCard title="Issuers" :padded="false" data-test="perm-issuers">
        <UiDataTable :items="issuers.items" :columns="issuerColumns" caption="Issuers" empty-title="No issuers" clickable :row-attrs="(i) => ({ 'data-test': 'perm-issuer-' + i.id })" @row-click="open('issuer', $event.id, $event.name)" />
      </UiCard>
    </div>
    <UiPermissionDrawer v-model="drawer" :title="'Permissions — ' + (target?.name || target?.id || '')" :grants="perms.grants.value" :subjects="perms.subjects.value" :levels="perms.levels.value" :can-manage="perms.canShare.value" expires :editable-level="false" :hint="perms.hint.value" :error="perms.error.value" :busy="perms.busy.value" data-test="permission-drawer" @search="perms.search" @grant="perms.onGrant" @revoke="perms.onRevoke" @change-level="perms.onChangeLevel" />
  </UiPage>
</template>
