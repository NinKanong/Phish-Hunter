import React from 'react';import {useAnalysisStore} from '../../store/analysisStore';
export function HostAnalysis(){const r:any=useAnalysisStore(s=>s.result);return <section className="panel"><h2>Victims / Assets / External Sources</h2><pre>{JSON.stringify({assets:r?.asset_profiles,victims:r?.victim_profiles,external_sources:r?.external_sources},null,2)}</pre></section>}
