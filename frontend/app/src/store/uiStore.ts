import {create} from 'zustand';
export type Tab='overview'|'cases'|'upload'|'jobs'|'iocs'|'reports'|'timeline'|'graph'|'artifacts'|'users'|'settings';
export const useUI=create<{tab:Tab;setTab:(tab:Tab)=>void}>(set=>({tab:'overview',setTab:tab=>set({tab})}));
