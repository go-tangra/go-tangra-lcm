import type { TangraModule } from './sdk';
import routes from './routes';
import { useLcmAuditLogStore } from './stores/lcm-audit-log.state';
import { useLcmCertificateStore } from './stores/lcm-certificate.state';
import { useLcmCertificateJobStore } from './stores/lcm-certificate-job.state';
import { useLcmIssuedCertificateStore } from './stores/lcm-issued-certificate.state';
import { useLcmCertificatePermissionStore } from './stores/lcm-certificate-permission.state';
import { useLcmIssuerStore } from './stores/lcm-issuer.state';
import { useLcmMtlsCertificateRequestStore } from './stores/lcm-mtls-certificate-request.state';
import { useLcmTenantSecretStore } from './stores/lcm-tenant-secret.state';
import enUS from './locales/en-US.json';

const lcmModule: TangraModule = {
  id: 'lcm',
  version: '1.0.0',
  routes,
  stores: {
    'lcm-audit-log': useLcmAuditLogStore,
    'lcm-certificate': useLcmCertificateStore,
    'lcm-certificate-job': useLcmCertificateJobStore,
    'lcm-issued-certificate': useLcmIssuedCertificateStore,
    'lcm-certificate-permission': useLcmCertificatePermissionStore,
    'lcm-issuer': useLcmIssuerStore,
    'lcm-mtls-certificate-request': useLcmMtlsCertificateRequestStore,
    'lcm-tenant-secret': useLcmTenantSecretStore,
  },
  locales: {
    'en-US': enUS,
  },
};

export default lcmModule;
