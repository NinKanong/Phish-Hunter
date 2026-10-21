declare module 'react' { export type ReactNode = any; export const StrictMode:any; export function useState<T=any>(v:T):[T,(x:T)=>void]; export function useRef<T=any>(v:T):{current:T}; export function useEffect(fn:()=>void|(()=>void),deps?:any[]):void; const React:any; export default React; }
declare module 'react-dom/client' { export function createRoot(el:Element):{render(node:any):void}; }
declare module 'react/jsx-runtime' { export const jsx:any; export const jsxs:any; export const Fragment:any; }
declare module 'axios' { const axios:any; export default axios; }
declare module 'zustand' { export function create<T=any>(fn:any):any; }
declare namespace React { type ReactNode = any; }
declare namespace JSX { interface IntrinsicElements {[elemName:string]:any} }
