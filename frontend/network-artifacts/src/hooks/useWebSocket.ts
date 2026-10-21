import {useEffect} from 'react';
import {jobSocket} from '../api/client';
import {useAnalysisStore} from '../store/analysisStore';
export function useJobSocket(jobId:string|null){const setJob=useAnalysisStore(s=>s.setJob);useEffect(()=>{if(!jobId)return;const ws=jobSocket(jobId);ws.onmessage=e=>{try{setJob(JSON.parse(e.data));}catch{}};return()=>ws.close();},[jobId,setJob]);}
