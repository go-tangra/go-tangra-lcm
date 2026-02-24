declare module 'shell/vben/stores' {
  import type { StoreDefinition } from 'pinia';
  export const useAccessStore: StoreDefinition;
  export const useUserStore: StoreDefinition;
}

declare module 'shell/vben/common-ui' {
  import type { Component } from 'vue';
  export const Page: Component;
  export function useVbenDrawer(options: any): [Component, any];
  export function useVbenForm(options: any): [Component, any];
  export type VbenFormProps = any;
}

declare module 'shell/vben/icons' {
  import type { Component } from 'vue';
  export const LucideEye: Component;
  export const LucideTrash: Component;
  export const LucidePencil: Component;
  export const LucidePlus: Component;
  export const LucideRefreshCw: Component;
  export const LucideXCircle: Component;
  export const LucideCheckCircle: Component;
  export const LucideShieldCheck: Component;
  export const LucideBuilding2: Component;
  export const LucideFileKey: Component;
  export const LucideFilePlus: Component;
  export const LucideAward: Component;
  export const LucideListTodo: Component;
  export const LucideKey: Component;
  export const LucideLockKeyhole: Component;
  export const LucideScrollText: Component;
  export const LucideDownload: Component;
  export const LucideCopy: Component;
  export const LucideRotateCw: Component;
  export const LucideKeyRound: Component;
  export const LucideTrash2: Component;
  export const LucideCheck: Component;
  export const LucideX: Component;
  export const LucideShieldX: Component;
}

declare module 'shell/vben/layouts' {
  import type { Component } from 'vue';
  export const BasicLayout: Component;
}

declare module 'shell/adapter/vxe-table' {
  export function useVbenVxeGrid(options: any): any;
  export type VxeGridProps = any;
}

declare module 'shell/locales' {
  export function $t(key: string, ...args: any[]): string;
}

declare module 'shell/stores' {
  export function useTenantStore(): any;
}
