import type { RouteRecordRaw } from 'vue-router'
import '@/main.css'

// Routes mounted by the platform shell under their own error boundary. They
// mirror lcmmanifest.Nav (services/lcm/pkg/lcmmanifest/manifest.go).
export const routes: RouteRecordRaw[] = [
  { path: '/lcm', name: 'lcm-dashboard', component: () => import('@/views/dashboard/index.vue'), meta: { module: 'lcm' } },
  { path: '/lcm/certificates', name: 'lcm-certificates', component: () => import('@/views/certificates/index.vue'), meta: { module: 'lcm' } },
  { path: '/lcm/issuers', name: 'lcm-issuers', component: () => import('@/views/issuers/index.vue'), meta: { module: 'lcm' } },
  { path: '/lcm/requests', name: 'lcm-requests', component: () => import('@/views/requests/index.vue'), meta: { module: 'lcm' } },
  { path: '/lcm/permissions', name: 'lcm-permissions', component: () => import('@/views/permissions/index.vue'), meta: { module: 'lcm' } },
  { path: '/lcm/secrets', name: 'lcm-secrets', component: () => import('@/views/secrets/index.vue'), meta: { module: 'lcm' } },
  { path: '/lcm/audit', name: 'lcm-audit', component: () => import('@/views/audit/index.vue'), meta: { module: 'lcm' } },
]
export default routes
