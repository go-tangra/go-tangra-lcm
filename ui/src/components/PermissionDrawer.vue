<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { usePermissions } from '@/stores/permissions'
import { useDirectory } from '@/stores/directory'
import { describe } from '@/api/client'
import { grantable, type Relation, type ResourceType, type SubjectType, type UserHit } from '@/api/types'

const model = defineModel<boolean>({ required: true })
const props = defineProps<{ resourceType: ResourceType; resourceId: string; resourceName?: string }>()
const store = usePermissions()
const dir = useDirectory()

const subjectType = ref<SubjectType>('user')
const subjectId = ref('')
const relation = ref<Relation>('viewer')
const expiresAt = ref('')
const err = ref('')
const busy = ref(false)
const userQuery = ref('')
const userHits = ref<UserHit[]>([])
const roleItems = computed(() => Object.values(dir.roles).map((r) => ({ title: r.display_name, value: r.slug })))

// Only a holder of the share permission may grant; the relation choices never
// exceed their own relation (grantable).
const canShare = computed(() => store.effective?.permissions?.share ?? false)
const options = computed<Relation[]>(() => grantable(store.effective?.relation ?? ''))

watch(
  () => [model.value, props.resourceId] as const,
  async ([open]) => {
    if (!open) return
    err.value = ''
    await Promise.all([store.load(props.resourceType, props.resourceId), dir.loadRoles()])
    await dir.resolveUsers(store.grants.map((g) => (g.subject_type === 'user' ? g.subject_id : undefined)))
  },
  { immediate: true },
)

watch(userQuery, async (q) => {
  userHits.value = await dir.searchUsers(q)
})

function subjectLabel(g: { subject_type: SubjectType; subject_id?: string }): string {
  if (g.subject_type === 'tenant') return 'Everyone in the tenant'
  if (g.subject_type === 'role') return 'Role: ' + dir.roleName(g.subject_id)
  return dir.userName(g.subject_id)
}

async function add(): Promise<void> {
  busy.value = true
  err.value = ''
  try {
    await store.grant({
      resource_type: props.resourceType,
      resource_id: props.resourceId,
      subject_type: subjectType.value,
      subject_id: subjectType.value === 'tenant' ? undefined : subjectId.value,
      relation: relation.value,
      expires_at: expiresAt.value || undefined,
    })
    subjectId.value = ''
    expiresAt.value = ''
  } catch (e) {
    err.value = describe(e)
  } finally {
    busy.value = false
  }
}

async function revoke(id: string): Promise<void> {
  err.value = ''
  try {
    await store.revoke(id)
  } catch (e) {
    err.value = describe(e)
  }
}
</script>

<template>
  <v-navigation-drawer v-model="model" location="right" temporary width="480" data-test="permission-drawer">
    <v-card flat>
      <v-card-title class="text-truncate">Permissions — {{ props.resourceName || props.resourceId }}</v-card-title>
      <v-card-text>
        <div class="text-caption text-medium-emphasis mb-2">Your relation: {{ store.effective?.relation || 'none' }}</div>
        <template v-if="canShare">
          <v-select v-model="subjectType" :items="['user', 'role', 'tenant']" label="Subject" density="compact" data-test="grant-subject-type" />
          <v-autocomplete
            v-if="subjectType === 'user'"
            v-model="subjectId"
            v-model:search="userQuery"
            :items="userHits.map((u) => ({ title: u.display_name, value: u.id }))"
            label="User"
            density="compact"
            data-test="grant-user"
          />
          <v-select v-else-if="subjectType === 'role'" v-model="subjectId" :items="roleItems" label="Role" density="compact" data-test="grant-role" />
          <v-select v-model="relation" :items="options" label="Relation" density="compact" data-test="grant-relation" />
          <v-text-field v-model="expiresAt" label="Expires (optional, ISO 8601)" density="compact" data-test="grant-expires" />
          <v-btn color="primary" size="small" :loading="busy" prepend-icon="mdi-account-plus-outline" data-test="grant-add" @click="add">Grant</v-btn>
        </template>
        <v-alert v-else type="info" variant="tonal" density="compact">You need the share permission to grant access here.</v-alert>
        <v-alert v-if="err" type="error" variant="tonal" density="compact" class="mt-2" data-test="grant-error">{{ err }}</v-alert>
        <v-divider class="my-3" />
        <v-list density="compact" data-test="grant-list">
          <v-list-item v-for="g in store.grants" :key="g.id" :data-test="'grant-row-' + g.id">
            <v-list-item-title>{{ subjectLabel(g) }}</v-list-item-title>
            <v-list-item-subtitle>
              {{ g.relation }}<span v-if="g.expires_at"> · expires {{ new Date(g.expires_at).toLocaleDateString() }}</span>
            </v-list-item-subtitle>
            <template #append>
              <v-btn v-if="canShare" icon="mdi-close" size="x-small" variant="text" :data-test="'grant-revoke-' + g.id" @click="revoke(g.id)" />
            </template>
          </v-list-item>
          <v-list-item v-if="!store.grants.length" title="No grants yet." />
        </v-list>
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn @click="model = false">Close</v-btn>
      </v-card-actions>
    </v-card>
  </v-navigation-drawer>
</template>
