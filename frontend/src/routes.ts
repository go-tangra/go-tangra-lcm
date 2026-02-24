import type { RouteRecordRaw } from 'vue-router';

const routes: RouteRecordRaw[] = [
  {
    path: '/lcm',
    name: 'CertificateManagement',
    component: () => import('shell/app-layout'),
    redirect: '/lcm/issuer',
    meta: {
      order: 2006,
      icon: 'lucide:shield-check',
      title: 'lcm.menu.moduleName',
      keepAlive: true,
      authority: ['platform:admin'],
    },
    children: [
      {
        path: 'issuer',
        name: 'IssuerManagement',
        meta: {
          icon: 'lucide:building-2',
          title: 'lcm.menu.issuer',
          authority: ['platform:admin'],
        },
        component: () => import('./views/issuer/index.vue'),
      },
      {
        path: 'certificate',
        name: 'CertificateList',
        meta: {
          icon: 'lucide:file-key',
          title: 'lcm.menu.mtlsCertificate',
          authority: ['platform:admin'],
        },
        component: () => import('./views/certificate/index.vue'),
      },
      {
        path: 'certificate-request',
        name: 'CertificateRequestManagement',
        meta: {
          icon: 'lucide:file-plus',
          title: 'lcm.menu.mtlsCertificateRequest',
          authority: ['platform:admin'],
        },
        component: () => import('./views/mtls-certificate-request/index.vue'),
      },
      {
        path: 'issued-certificate',
        name: 'IssuedCertificateManagement',
        meta: {
          icon: 'lucide:award',
          title: 'lcm.menu.issuedCertificate',
          authority: ['platform:admin'],
        },
        component: () => import('./views/issued-certificate/index.vue'),
      },
      {
        path: 'certificate-job',
        name: 'CertificateJobManagement',
        meta: {
          icon: 'lucide:list-todo',
          title: 'lcm.menu.certificateJob',
          authority: ['platform:admin'],
        },
        component: () => import('./views/certificate-job/index.vue'),
      },
      {
        path: 'certificate-permission',
        name: 'CertificatePermissionManagement',
        meta: {
          icon: 'lucide:key',
          title: 'lcm.menu.certificatePermission',
          authority: ['platform:admin'],
        },
        component: () => import('./views/certificate-permission/index.vue'),
      },
      {
        path: 'tenant-secret',
        name: 'TenantSecretManagement',
        meta: {
          icon: 'lucide:lock-keyhole',
          title: 'lcm.menu.tenantSecret',
          authority: ['platform:admin'],
        },
        component: () => import('./views/tenant-secret/index.vue'),
      },
      {
        path: 'audit-log',
        name: 'LcmAuditLogManagement',
        meta: {
          icon: 'lucide:scroll-text',
          title: 'lcm.menu.auditLog',
          authority: ['platform:admin'],
        },
        component: () => import('./views/audit-log/index.vue'),
      },
    ],
  },
];

export default routes;
