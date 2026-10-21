export function Card({title,children,sub}:{title:string;children:any;sub?:string}){return <section className="card"><div className="card-head"><div><b>{title}</b>{sub&&<small>{sub}</small>}</div></div>{children}</section>}
export function Badge({children,tone='neutral'}:{children:any;tone?:string}){return <span className={`badge ${tone}`}>{children}</span>}
