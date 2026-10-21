import axios from 'axios';
export const api = axios.create({baseURL:'/api/v1/pcap',withCredentials:true,timeout:30000});
api.interceptors.request.use(config=>{const match=document.cookie.match(/(?:^|; )phishhunter_csrf=([^;]+)/);if(match)config.headers['X-CSRF-Token']=decodeURIComponent(match[1]);return config;});
export async function uploadArtifacts(files:File[]) { const body=new FormData(); files.forEach(f=>body.append('files',f,f.name)); const r=await api.post('/upload',body); return r.data as {job_id:string;status:string;artifacts:unknown[]}; }
export async function startAnalysis(id:string){return (await api.post(`/analyze/${encodeURIComponent(id)}`)).data;}
export async function getJob(id:string){return (await api.get(`/jobs/${encodeURIComponent(id)}`)).data;}
export async function getCapabilities(){return (await api.get('/capabilities')).data;}
export async function saveJob(id:string){return (await api.post(`/jobs/${encodeURIComponent(id)}/save`)).data;}
export function jobSocket(id:string){const protocol=location.protocol==='https:'?'wss':'ws';return new WebSocket(`${protocol}://${location.host}/api/v1/pcap/ws/${encodeURIComponent(id)}`);}
