import React from 'react';import {useAnalysisStore} from '../../store/analysisStore';
export function BehaviorStory(){const r:any=useAnalysisStore(s=>s.result);return <section className="panel"><h2>Attacker Behaviour Reconstruction</h2><p>This is an evidence-led reconstruction, not an attribution claim.</p><pre>{JSON.stringify(r?.behavioral_analysis,null,2)}</pre></section>}
