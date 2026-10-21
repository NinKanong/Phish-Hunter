import type {ReactNode} from 'react';
export function Card({title,children,action}:{title?:string;children:ReactNode;action?:ReactNode;key?:string|number}){return <section className="card">{title&&<div className="card-head"><h3>{title}</h3>{action}</div>}{children}</section>}
export function Badge({children,tone='neutral'}:{children:ReactNode;tone?:string;key?:string|number}){return <span className={`badge ${tone}`}>{children}</span>}
export function Metric({label,value,sub}:{label:string;value:ReactNode;sub?:ReactNode}){return <div className="metric"><span>{label}</span><strong>{value}</strong>{sub&&<small>{sub}</small>}</div>}
export function Empty({children}:{children:ReactNode}){return <div className="empty">{children}</div>}
