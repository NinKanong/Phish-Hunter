import React from 'react';import {useAnalysisStore} from '../../store/analysisStore';
export function ProtocolAnalysis(){const r:any=useAnalysisStore(s=>s.result);return <section className="panel"><h2>Protocol / TLS Analysis</h2><pre>{JSON.stringify({protocol:r?.protocol_analysis,tls:r?.tls_analysis,certificates:r?.certificate_analysis,ciphers:r?.cipher_analysis},null,2)}</pre></section>}
