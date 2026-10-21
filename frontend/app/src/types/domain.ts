export type User={id:number;email:string;tenant_id:number;is_admin:boolean;profile?:{display_name:string;job_title:string}};
export type Summary={users:number;investigations:number;running_jobs:number;high_risk:number;cases:number;reports:number;iocs:number;artifacts:number;audit_events:number};
export type Job={job_id:string;status:string;progress:number;message:string;created_at:string;started_at?:string;completed_at?:string;duration_seconds?:number;result?:any;error?:string};
export type CaseItem={id:number;title:string;status:string;priority:string;notes:string;created_at:string};
export type IOC={id:number;kind:string;value:string;source_scan_id:number;created_at:string};
export type Report={id:number;scan_id:number;title:string;format:string;created_at:string};
