import {useEffect,useState} from 'react'; import {jobSocket} from '../api/client';
export function useLiveJob(id?:string){const [state,setState]=useState<any>(null);useEffect(()=>{if(!id)return;const ws=jobSocket(id);ws.onmessage=e=>setState(JSON.parse(e.data));return()=>ws.close()},[id]);return state}
