import {create} from 'zustand';
import type {Artifact,JobStatus,NetworkResult} from '../types/network';
interface State { files:File[]; job:JobStatus|null; result:NetworkResult|null; activeTab:string; setFiles:(x:File[])=>void; setJob:(x:JobStatus|null)=>void; setResult:(x:NetworkResult|null)=>void; setTab:(x:string)=>void; }
export const useAnalysisStore=create<State>(set=>({files:[],job:null,result:null,activeTab:'overview',setFiles:x=>set({files:x}),setJob:x=>set({job:x,result:x?.result??null}),setResult:x=>set({result:x}),setTab:x=>set({activeTab:x})}));
