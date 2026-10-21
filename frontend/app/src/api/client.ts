const base='/api/v1';
function csrf(){const m=document.cookie.match(/(?:^|; )phishhunter_csrf=([^;]+)/);return m?decodeURIComponent(m[1]):'';}
async function request<T>(path:string, init:RequestInit={}){const headers=new Headers(init.headers); if(init.method&&init.method!=='GET'){headers.set('X-CSRF-Token',csrf());headers.set('Content-Type',headers.get('Content-Type')||'application/json');} const r=await fetch(base+path,{...init,headers,credentials:'include'}); if(!r.ok){const t=await r.text(); throw new Error(t||`${r.status} ${r.statusText}`)} return r.status===204?undefined as T:await r.json() as T;}
export const api={
 me:()=>request<any>('/auth/me'), summary:()=>request<any>('/dashboard/summary'),
 users:()=>request<any[]>('/users'), createUser:(body:any)=>request<any>('/users',{method:'POST',body:JSON.stringify(body)}), updateUser:(id:number,body:any)=>request<any>(`/users/${id}`,{method:'PATCH',body:JSON.stringify(body)}),
 cases:()=>request<any[]>('/cases'), createCase:(body:any)=>request<any>('/cases',{method:'POST',body:JSON.stringify(body)}), caseDetail:(id:number)=>request<any>(`/cases/${id}`), updateCase:(id:number,body:any)=>request<any>(`/cases/${id}`,{method:'PATCH',body:JSON.stringify(body)}), linkScan:(caseId:number,scanId:number)=>request<any>(`/cases/${caseId}/link-scan/${scanId}`,{method:'POST'}),
 iocs:()=>request<any[]>('/iocs'), reports:()=>request<any[]>('/reports'), report:(id:number)=>request<any>(`/reports/${id}`), jobs:()=>request<any[]>('/jobs'), job:(id:string)=>request<any>(`/jobs/${id}`), startJob:(id:string)=>request<any>(`/jobs/${id}/start`,{method:'POST'}),
 upload:async(files:File[])=>{const f=new FormData();files.forEach(x=>f.append('files',x));const r=await fetch(base+'/artifacts',{method:'POST',body:f,credentials:'include',headers:{'X-CSRF-Token':csrf()}});if(!r.ok)throw new Error(await r.text());return r.json();},
 artifacts:()=>request<any[]>('/artifacts')
};
export function jobSocket(id:string){const p=location.protocol==='https:'?'wss':'ws';return new WebSocket(`${p}://${location.host}${base}/jobs/ws/${encodeURIComponent(id)}`)}
