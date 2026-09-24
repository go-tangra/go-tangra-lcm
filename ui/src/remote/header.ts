import '@/main.css'
import HeaderCert from '@/components/HeaderCert.vue'

// The shell renders this in its app bar (contracts/shell-changes.md). It opens
// the module's live stream and shows a badge for certificates expiring soon; it
// renders nothing (and opens no connection) for a person without
// certificates:read, which the shell only mounts for modules the person can reach.
export default HeaderCert
