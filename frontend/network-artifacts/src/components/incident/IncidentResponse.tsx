import React from 'react';import {useAnalysisStore} from '../../store/analysisStore';
export function IncidentResponse(){const r:any=useAnalysisStore(s=>s.result);return <section className="panel"><h2>Incident Response Workflow</h2><pre>{JSON.stringify(r?.incident_response,null,2)}</pre></section>}
