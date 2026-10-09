import React, {useEffect, useMemo, useState} from 'react';
import * as Icons from 'lucide-react';
import {Area, AreaChart, Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis} from 'recharts';
import './command-center-v2.css';

const API = (import.meta.env.VITE_API_URL || 'https://psv-guardrail.onrender.com/api').replace(/\/$/, '');
const MODES = [
  ['COMMAND', 'Command', Icons.RadioTower],
  ['ALERT QUEUE', 'Alerts', Icons.ShieldAlert],
  ['INCIDENT BOARD', 'Incidents', Icons.Siren],
  ['EVENT CONSOLE', 'Events', Icons.SquareTerminal],
  ['NETWORK', 'Network', Icons.Waypoints],
  ['ASSETS', 'Assets', Icons.MonitorCog],
  ['INTELLIGENCE', 'Intel', Icons.Crosshair],
  ['REPORTS', 'Reports', Icons.ChartNoAxesCombined],
];
const MODE_BY_HASH = Object.fromEntries(MODES.map(([,value])=>[value.toLowerCase(),value]));
const SEVERITY = {Critical:'#ff5d66', High:'#f4a340', Medium:'#e1c453', Low:'#4bc9a6', Informational:'#61a9d8'};
const api = (path, options) => fetch(`${API}${path}`, options).then(async response => {
  if (!response.ok) throw new Error((await response.json().catch(()=>null))?.detail || 'SOC data service unavailable');
  return response.json();
});
const timeOnly = value => value ? new Date(value).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit', hour12:false}) : '--:--:--';
const shortDate = value => value ? new Date(value).toLocaleString('en-GB', {month:'short',day:'2-digit',hour:'2-digit',minute:'2-digit',hour12:false}) : '—';
const id = (prefix, value, width=4) => `${prefix}-${String(value).padStart(width,'0')}`;
const codeFor = event => ({Authentication:'AUTH', Network:'NET', Endpoint:'EDR', Malware:'MAL', Firewall:'FW', VPN:'VPN', 'Privilege Escalation':'PRIV', 'Access Control':'ACL'})[event?.event_type] || 'SYS';

export default function CommandCenterApp(){
  const [mode,setMode] = useState(()=>MODE_BY_HASH[location.hash.slice(1).toLowerCase()] || 'Command');
  const [data,setData] = useState({});
  const [loading,setLoading] = useState(true);
  const [error,setError] = useState('');
  const [selectedAlert,setSelectedAlert] = useState(null);
  const [selectedNode,setSelectedNode] = useState(null);
  const [clock,setClock] = useState(new Date());
  const [streamOffset,setStreamOffset] = useState(0);
  const [selectedResponse,setSelectedResponse] = useState(null);
  const [responseComplete,setResponseComplete] = useState(false);
  const [responseLedger,setResponseLedger] = useState([]);
  const prepareResponse = alert => {setSelectedResponse(alert);setResponseComplete(false);};
  const recordDryRun = () => {
    if(!selectedResponse) return;
    setResponseLedger(items=>[{
      id: `${Date.now()}-${selectedResponse.id}`,
      timestamp: new Date().toISOString(),
      alertId: selectedResponse.id,
      alertType: selectedResponse.alert_type,
      risk: riskScore(selectedResponse),
      mode: 'DRY RUN — NO SYSTEM CHANGES'
    },...items].slice(0,10));
    setResponseComplete(true);
  };

  const load = async () => {
    setLoading(true); setError('');
    try{
      const [stats,alerts,incidents,events,endpoints,network,intel,reports] = await Promise.all(
        ['dashboard/stats','alerts','incidents','events','endpoints','network/events','threat-intelligence','reports/summary'].map(path=>api(`/${path}`))
      );
      setData({stats,alerts,incidents,events,endpoints,network,intel,reports});
    }catch(err){setError(err.message)} finally{setLoading(false)}
  };
  useEffect(()=>{load()},[]);
  useEffect(()=>{const timer=setInterval(()=>setClock(new Date()),1000);return()=>clearInterval(timer)},[]);
  useEffect(()=>{const timer=setInterval(()=>setStreamOffset(value=>value+1),4500);return()=>clearInterval(timer)},[]);
  const switchMode = next => {setMode(next); location.hash=next==='Command'?'':next.toLowerCase()};
  const updateAlert = async status => {
    if(!selectedAlert) return;
    const changed = await api(`/alerts/${selectedAlert.id}`,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({status})});
    setSelectedAlert(changed); await load();
  };
  const updateIncident = async (incident,status) => {
    await api(`/incidents/${incident.id}`,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({status})});
    await load();
  };

  return <div className="cc-shell">
    <StatusBar data={data} clock={clock}/>
    <ModeSwitcher mode={mode} onChange={switchMode} data={data}/>
    {loading ? <SystemState icon={Icons.LoaderCircle} title="Synchronizing telemetry" text="Establishing secure data channels…" spin/> :
      error ? <SystemState icon={Icons.Unplug} title="Telemetry link offline" text={error} action={load}/> :
      <main className="cc-stage">
        {mode==='Command' && <CommandView data={data} offset={streamOffset} investigate={setSelectedAlert} inspectNode={node=>{setSelectedNode(node);switchMode('Network')}} openQueue={()=>switchMode('Alerts')}/>}
        {mode==='Alerts' && <AlertQueue data={data} investigate={setSelectedAlert}/>}
        {mode==='Incidents' && <IncidentBoard data={data} updateIncident={updateIncident}/>}
        {mode==='Events' && <EventConsole data={data}/>}
        {mode==='Network' && <NetworkWorkspace data={data} selectedNode={selectedNode} inspectNode={setSelectedNode}/>}
        {mode==='Assets' && <AssetMatrix data={data}/>}
        {mode==='Intel' && <Intelligence data={data}/>}
        {mode==='Reports' && <Reports data={data}/>}
      </main>}
    {selectedAlert && <InvestigationDrawer alert={selectedAlert} close={()=>setSelectedAlert(null)} action={updateAlert} prepareContainment={prepareResponse}/>}
    {selectedResponse && <ResponsePreview alert={selectedResponse} complete={responseComplete} ledger={responseLedger} onRun={recordDryRun} onClose={()=>setSelectedResponse(null)}/> }
  </div>
}

function StatusBar({data,clock}){
  const cards=data.stats?.cards||{};
  return <header className="status-bar">
    <div className="cc-brand"><span className="cc-mark"><Icons.ShieldCheck size={19}/></span><div><strong className="gr-wordmark">GR<span> GUARDRAIL</span></strong><small>SECURITY OPERATIONS</small></div></div>
    <div className="ops-state"><i/><div><small>SOC STATUS</small><b>OPERATIONAL</b></div></div>
    <div className="status-metrics">
      <StatusMetric label="EVENTS / MIN" value="24.8" trend="LIVE"/>
      <StatusMetric label="ACTIVE INCIDENTS" value={cards.open_incidents??'—'} attention/>
      <StatusMetric label="ENDPOINTS" value={cards.endpoints??'—'} suffix="/ 20"/>
      <StatusMetric label="UTC +03" value={clock.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false})} mono/>
    </div>
    <button className="analyst-chip"><span>GR</span><div><b>GR Analyst</b><small>Security Operations</small></div><Icons.ChevronDown size={14}/></button>
  </header>
}
function StatusMetric({label,value,suffix,trend,attention}){return <div className={`status-metric ${attention?'attention':''}`}><small>{label}</small><b>{value} {suffix&&<em>{suffix}</em>}</b>{trend&&<span>{trend}</span>}</div>}
function ModeSwitcher({mode,onChange,data}){return <nav className="mode-switcher"><div className="mode-list">{MODES.map(([label,value,Icon])=><button key={value} className={mode===value?'active':''} onClick={()=>onChange(value)}><Icon size={14}/><span>{label}</span>{value==='Alerts'&&<em>{data.alerts?.filter(a=>a.status==='New').length||0}</em>}</button>)}</div><div className="data-class"><Icons.LockKeyhole size={12}/> DEMO DATA · INTERNAL</div></nav>}
function SystemState({icon:Icon,title,text,action,spin}){return <div className="system-state"><Icon className={spin?'spin':''}/><h2>{title}</h2><p>{text}</p>{action&&<button onClick={action}>RETRY LINK</button>}</div>}

function CommandView({data,offset,investigate,inspectNode,openQueue}){
  const events=data.events||[]; const alerts=data.alerts||[];
  const stream=Array.from({length:10},(_,i)=>events[(offset+i)%events.length]).filter(Boolean);
  return <div className="command-grid">
    <aside className="activity-rail zone">
      <ZoneHead eyebrow="INGEST / LIVE" title="Event stream" status="STREAMING"/>
      <div className="stream-rate"><Icons.Activity size={14}/><b>24.8</b><span>events / minute</span><i/></div>
      <div className="event-stream">{stream.map((event,index)=><EventTick event={event} key={`${event.id}-${offset}-${index}`}/>)}</div>
      <div className="rail-foot"><span>124 records buffered</span><span>0 dropped</span></div>
    </aside>
    <section className="threat-workspace zone">
      <ZoneHead eyebrow="CORRELATION / 8H WINDOW" title="Threat activity" status="LIVE TRAFFIC"/>
      <ThreatTopology data={data} onNode={inspectNode}/>
      <div className="topology-readout"><div><small>EXTERNAL SOURCES</small><b>06</b></div><div><small>FLAGGED PATHS</small><b className="amber">09</b></div><div><small>BLOCKED FLOWS</small><b>17</b></div><div className="readout-note"><Icons.ScanSearch size={16}/><span>Correlation engine is monitoring authentication, endpoint and network telemetry.</span></div></div>
    </section>
    <aside className="threat-rail zone">
      <ZoneHead eyebrow="TRIAGE / PRIORITY" title="Active threats" status={`${alerts.filter(a=>a.status!=='Resolved').length} OPEN`}/>
      <div className="threat-stack">{alerts.filter(a=>['Critical','High'].includes(a.severity)).slice(0,5).map(alert=><ThreatItem key={alert.id} alert={alert} investigate={investigate}/>)}</div>
      <button className="queue-link" onClick={openQueue}>OPEN FULL ALERT QUEUE <Icons.ArrowRight size={13}/></button>
    </aside>
  </div>
}
function ZoneHead({eyebrow,title,status}){return <div className="zone-head"><div><small>{eyebrow}</small><h2>{title}</h2></div><span><i/>{status}</span></div>}
function EventTick({event}){return <div className="event-tick"><time>{timeOnly(event.timestamp)}</time><b className={`event-code ${codeFor(event).toLowerCase()}`}>{codeFor(event)}</b><div><strong>{event.description.split('. ')[0]}</strong><small><span>src</span>={event.source_ip} <span>host</span>={event.host}</small></div><i style={{background:SEVERITY[event.severity]}}/></div>}
function ThreatItem({alert,investigate}){return <article className={`threat-item ${alert.severity.toLowerCase()}`}><div className="threat-top"><b><i/>{alert.severity.toUpperCase()}</b><time>{timeOnly(alert.timestamp)}</time></div><h3>{alert.alert_type}</h3><div className="threat-path"><span>{alert.source_ip}</span><Icons.MoveRight size={13}/><span>{alert.destination}</span></div><p>{alert.detection_reason}</p><div className="threat-meta"><span>{alert.status}</span><span>SIM · T1110</span></div><button onClick={()=>investigate(alert)}>INVESTIGATE <Icons.ScanSearch size={13}/></button></article>}

const NODES=[
  {id:'internet',label:'EXTERNAL',sub:'6 sources',x:450,y:43,type:'external'},
  {id:'firewall',label:'EDGE FIREWALL',sub:'17 blocked',x:450,y:128,type:'control'},
  {id:'gateway',label:'CORE GATEWAY',sub:'10.20.0.1',x:450,y:220,type:'control'},
  {id:'ws1',label:'FIN-WS-01',sub:'10.20.10.20',x:165,y:340,type:'endpoint'},
  {id:'ws3',label:'ENG-WS-03',sub:'10.20.10.22',x:350,y:360,type:'warning'},
  {id:'server',label:'FILE-SERVER',sub:'172.16.2.14',x:555,y:360,type:'server'},
  {id:'dc',label:'DOMAIN CTRL',sub:'172.16.2.10',x:740,y:340,type:'critical'},
];
const EDGES=[['internet','firewall','hostile'],['firewall','gateway','active'],['gateway','ws1','normal'],['gateway','ws3','hostile'],['gateway','server','normal'],['gateway','dc','active'],['ws3','server','lateral']];
function ThreatTopology({onNode,large=false}){
  const byId=Object.fromEntries(NODES.map(node=>[node.id,node]));
  return <div className={`topology ${large?'large':''}`}><div className="topology-grid"/><svg viewBox="0 0 900 430" role="img" aria-label="Simulated security network topology">
    <defs><marker id="arrow" viewBox="0 0 10 10" refX="7" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#71877e"/></marker></defs>
    {EDGES.map(([from,to,type])=>{const a=byId[from],b=byId[to];return <g key={`${from}-${to}`} className={`edge ${type}`}><line x1={a.x} y1={a.y+20} x2={b.x} y2={b.y-20} markerEnd="url(#arrow)"/><circle r="3"><animateMotion dur={type==='hostile'?'2.4s':'4s'} repeatCount="indefinite" path={`M${a.x},${a.y+20} L${b.x},${b.y-20}`}/></circle></g>})}
    {NODES.map(node=><g className={`topology-node ${node.type}`} transform={`translate(${node.x},${node.y})`} key={node.id} onClick={()=>onNode?.(node)} tabIndex="0"><circle className="node-range" r="37"/><rect x="-61" y="-25" width="122" height="50" rx="3"/><circle className="node-status" cx="-47" cy="-11" r="4"/><text className="node-label" textAnchor="middle" y="-1">{node.label}</text><text className="node-sub" textAnchor="middle" y="14">{node.sub}</text></g>)}
  </svg><div className="topology-legend"><span><i className="normal"/>NORMAL</span><span><i className="warning"/>SUSPICIOUS</span><span><i className="critical"/>CRITICAL PATH</span></div></div>
}

function AlertQueue({data,investigate}){
  const [severity,setSeverity]=useState('All'); const [query,setQuery]=useState('');
  const alerts=(data.alerts||[]).filter(a=>(severity==='All'||a.severity===severity)&&(!query||Object.values(a).join(' ').toLowerCase().includes(query.toLowerCase())));
  return <div className="mode-page"><PageTitle overline="TRIAGE WORKSPACE" title="Alert queue" text="Prioritized detections ready for analyst review." count={`${alerts.length} DETECTIONS`}/><div className="queue-toolbar"><div className="severity-tabs">{['All','Critical','High','Medium','Low'].map(value=><button className={severity===value?'active':''} onClick={()=>setSeverity(value)} key={value}>{value.toUpperCase()}<span>{value==='All'?data.alerts.length:data.alerts.filter(a=>a.severity===value).length}</span></button>)}</div><label><Icons.Search size={14}/><input value={query} onChange={e=>setQuery(e.target.value)} placeholder="Search IP, host, detection…"/></label></div><section className="alert-queue">{alerts.map(alert=><article className="queue-row" key={alert.id}><div className="severity-rail" style={{background:SEVERITY[alert.severity]}}/><div className="queue-id"><small>{id('ALT',alert.id)}</small><time>{timeOnly(alert.timestamp)}</time></div><div className="queue-detection"><div><b style={{color:SEVERITY[alert.severity]}}>{alert.severity.toUpperCase()}</b><span>{alert.status}</span><span className="technique">SIM MAPPING · T1110</span></div><h3>{alert.alert_type}</h3><p>{alert.description}</p></div><div className="queue-route"><small>SOURCE</small><b>{alert.source_ip}</b><Icons.ArrowRight size={15}/><small>TARGET</small><b>{alert.destination}</b></div><div className="queue-context"><span><Icons.UserRound size={12}/>{alert.user}</span><span><Icons.Monitor size={12}/>{alert.host}</span></div><button onClick={()=>investigate(alert)}>INVESTIGATE <Icons.ChevronRight size={14}/></button></article>)}</section></div>
}
function InvestigationDrawer({alert,close,action,prepareContainment}){
  const timeline=[
    ['-05m','Multiple failed authentication attempts','Authentication sensor'],
    ['-03m',`Account targeted: ${alert.user}`,'Identity telemetry'],
    ['-02m',`Activity observed on ${alert.host}`,'Endpoint correlation'],
    ['-01m',`Connection from ${alert.source_ip}`,'Network sensor'],
    ['NOW','SOC detection generated','SentinelIQ rule engine'],
  ];
  return <div className="drawer-backdrop" onMouseDown={close}><aside className="investigation-drawer" onMouseDown={e=>e.stopPropagation()}><header><div><small>INVESTIGATION / {id('ALT',alert.id)}</small><h2>{alert.alert_type}</h2></div><button onClick={close}><Icons.X size={18}/></button></header><div className="investigation-status"><span style={{color:SEVERITY[alert.severity]}}><i style={{background:SEVERITY[alert.severity]}}/>{alert.severity.toUpperCase()}</span><span>{alert.status.toUpperCase()}</span><time>{shortDate(alert.timestamp)}</time></div><section className="case-summary"><p>{alert.description}</p><div className="case-grid"><CaseFact label="SOURCE IP" value={alert.source_ip}/><CaseFact label="DESTINATION" value={alert.destination}/><CaseFact label="USER" value={alert.user}/><CaseFact label="ENDPOINT" value={alert.host}/></div></section><section className="risk-assessment">
      <div className="risk-score"><small>EXPLAINABLE RISK</small><strong>{riskScore(alert)}<span>/100</span></strong><i><b style={{width:`${riskScore(alert)}%`}}/></i></div>
      <div className="risk-reasons"><b>WHY THIS SCORE?</b>{riskReasons(alert).map(reason=><p key={reason}><Icons.CheckCircle2 size={13}/>{reason}</p>)}</div>
    </section><section className="timeline"><div className="drawer-section-title"><span>INCIDENT TIMELINE</span><small>SIMULATED CORRELATION</small></div>{timeline.map(([time,title,source],index)=><div className={`timeline-entry ${index===timeline.length-1?'current':''}`} key={title}><time>{time}</time><i/><div><b>{title}</b><small>{source}</small></div></div>)}</section><section className="detection-box"><div className="drawer-section-title"><span>DETECTION RATIONALE</span></div><p>{alert.detection_reason}</p><small>Educational technique mapping: Credential Access / Brute Force (simulated only)</small></section><section className="response-box"><Icons.Lightbulb size={15}/><div><b>RECOMMENDED RESPONSE</b><p>{alert.recommended_response}</p></div></section><footer><button onClick={()=>action('Investigating')}><Icons.Check size={14}/>ACKNOWLEDGE</button><button onClick={()=>action('Investigating')} className="active"><Icons.ScanSearch size={14}/>INVESTIGATE</button><button onClick={()=>prepareContainment(alert)} className="contain"><Icons.ShieldBan size={14}/>PREVIEW RESPONSE</button><button onClick={()=>action('Investigating')}><Icons.ArrowUpRight size={14}/>ESCALATE</button><button onClick={()=>action('Resolved')}><Icons.CircleCheck size={14}/>RESOLVE</button></footer></aside></div>
}
function CaseFact({label,value}){return <div><small>{label}</small><b>{value}</b></div>}

const BOARD_COLUMNS=['New','Investigating','Contained','Resolved'];
function IncidentBoard({data,updateIncident}){return <div className="mode-page"><PageTitle overline="RESPONSE WORKFLOW" title="Incident board" text="Move investigations through containment and resolution." count={`${data.incidents.length} CASES`}/><div className="incident-board">{BOARD_COLUMNS.map((status,index)=>{const items=data.incidents.filter(item=>item.status===status||(status==='Resolved'&&item.status==='Closed'));return <section className={`board-column ${status.toLowerCase()}`} key={status}><header><div><i/><h2>{status.toUpperCase()}</h2></div><span>{items.length}</span></header><div>{items.map(item=><article className="incident-card" key={item.id}><div className="incident-card-top"><span style={{color:SEVERITY[item.severity]}}>{item.severity.toUpperCase()}</span><small>{id('INC',item.id)}</small></div><h3>{item.title}</h3><p>{item.summary}</p><div className="incident-owner"><span>{item.assigned_analyst==='Waleed Alharbi'?'WA':'SOC'}</span><b>{item.assigned_analyst}</b></div><div className="incident-time"><span>UPDATED</span><time>{shortDate(item.last_updated)}</time></div><footer>{index>0&&<button title="Move back" onClick={()=>updateIncident(item,BOARD_COLUMNS[index-1])}><Icons.ArrowLeft size={14}/></button>}<button className="open-case">OPEN CASE</button>{index<BOARD_COLUMNS.length-1&&<button title="Advance status" onClick={()=>updateIncident(item,BOARD_COLUMNS[index+1])}><Icons.ArrowRight size={14}/></button>}</footer></article>)}</div></section>})}</div></div>}

function EventConsole({data}){
  const [filter,setFilter]=useState('ALL'); const [search,setSearch]=useState('');
  const eventTypes={AUTH:'Authentication',NETWORK:'Network',ENDPOINT:'Endpoint',FIREWALL:'Firewall',VPN:'VPN',MALWARE:'Malware'};
  const rows=data.events.filter(event=>(filter==='ALL'||event.event_type===eventTypes[filter])&&(!search||Object.values(event).join(' ').toLowerCase().includes(search.toLowerCase())));
  return <div className="console-page"><PageTitle overline="RAW TELEMETRY" title="Event console" text="Normalized security events from all monitored sources." count={`${rows.length} RECORDS`}/><div className="console-toolbar"><div>{['ALL','AUTH','NETWORK','ENDPOINT','FIREWALL','VPN','MALWARE'].map(value=><button className={filter===value?'active':''} onClick={()=>setFilter(value)} key={value}>{value}</button>)}</div><label><span>$</span><input value={search} onChange={e=>setSearch(e.target.value)} placeholder="filter telemetry"/></label><button className="pause"><Icons.Pause size={12}/> PAUSE STREAM</button></div><section className="terminal-console"><header><span>gr-guardrail@collector-01</span><span>channel=security-events</span><span className="connected"><i/>CONNECTED</span></header><div className="log-lines">{rows.slice(0,60).map(event=><div className="log-entry" key={event.id}><span className="log-index">{String(event.id).padStart(4,'0')}</span><time>[{timeOnly(event.timestamp)}]</time><b className={codeFor(event).toLowerCase()}>{codeFor(event)}_{event.description.toLowerCase().includes('failed')?'FAIL':'EVENT'}</b><span>src=<em>{event.source_ip}</em></span><span>user=<em>{event.username}</em></span><span>host=<em>{event.host}</em></span><span>severity=<em style={{color:SEVERITY[event.severity]}}>{event.severity.toUpperCase()}</em></span><p>{event.description}</p></div>)}</div><footer><span>Showing {Math.min(rows.length,60)} / {rows.length}</span><span>Buffer healthy · latency 34ms</span></footer></section></div>}

function NetworkWorkspace({data,selectedNode,inspectNode}){const node=selectedNode||NODES[4];return <div className="mode-page network-page"><PageTitle overline="NETWORK OBSERVABILITY" title="Connection topology" text="Inspect simulated traffic paths, boundaries, and targeted assets." count="LIVE MAP"/><div className="network-layout"><section className="network-canvas zone"><ThreatTopology data={data} onNode={inspectNode} large/></section><aside className="node-inspector zone"><ZoneHead eyebrow="SELECTED NODE" title={node.label} status={node.type==='critical'?'AT RISK':'MONITORED'}/><div className={`node-orb ${node.type}`}><Icons.Server size={26}/><i/></div><dl><div><dt>ADDRESS</dt><dd>{node.sub}</dd></div><div><dt>RISK SCORE</dt><dd>{node.type==='critical'?'92 / 100':'58 / 100'}</dd></div><div><dt>OPEN ALERTS</dt><dd>{node.type==='critical'?'04':'02'}</dd></div><div><dt>LAST ACTIVITY</dt><dd>12 sec ago</dd></div><div><dt>SECURITY AGENT</dt><dd>HEALTHY</dd></div></dl><div className="node-events"><b>RECENT CONNECTIONS</b>{data.network.slice(0,4).map(item=><div key={item.id}><span>{item.protocol}:{item.port}</span><small>{item.action}</small><em>{item.risk_score}</em></div>)}</div><button><Icons.ScanSearch size={14}/>INVESTIGATE ASSET</button></aside></div></div>}

function AssetMatrix({data}){return <div className="mode-page"><PageTitle overline="ENDPOINT TELEMETRY" title="Asset matrix" text="Operational posture of monitored workstations and servers." count={`${data.endpoints.length} ENDPOINTS`}/><section className="asset-matrix">{data.endpoints.map(endpoint=><article key={endpoint.id} className={`asset-unit ${endpoint.status.toLowerCase()}`}><header><span><Icons.Monitor size={16}/></span><div><h3>{endpoint.hostname}</h3><small>{endpoint.ip_address}</small></div><i/></header><p>{endpoint.operating_system}</p><div><span>RISK <b style={{color:SEVERITY[endpoint.risk_level]}}>{endpoint.risk_level.toUpperCase()}</b></span><span>ALERTS <b>{String(endpoint.open_alerts).padStart(2,'0')}</b></span></div><footer><span>{endpoint.security_agent}</span><time>{shortDate(endpoint.last_seen)}</time></footer></article>)}</section></div>}
function Intelligence({data}){return <div className="mode-page"><PageTitle overline="INDICATOR REPOSITORY" title="Threat intelligence" text="Fictional observables available for correlation and analyst context." count={`${data.intel.length} INDICATORS`}/><section className="intel-grid">{data.intel.map(item=><article key={item.id}><header><span><Icons.Crosshair size={13}/>{item.indicator_type.toUpperCase()}</span><b style={{color:SEVERITY[item.threat_level]}}>{item.threat_level.toUpperCase()}</b></header><h3>{item.indicator}</h3><div className="confidence-meter"><i style={{width:`${item.confidence}%`}}/><span>{item.confidence}% CONFIDENCE</span></div><footer><span>FIRST {shortDate(item.first_seen)}</span><span>LAST {shortDate(item.last_seen)}</span><b>{item.status}</b></footer></article>)}</section></div>}
function Reports({data}){const stats=data.stats;return <div className="mode-page"><PageTitle overline="OPERATIONAL ANALYTICS" title="Security reports" text="Monitoring trends for this fictional portfolio environment." count="8H WINDOW"/><section className="report-strip"><div><small>RESOLUTION RATE</small><b>{data.reports.resolution_rate}%</b><span>+8% period over period</span></div><div><small>TOP CATEGORY</small><b>AUTHENTICATION</b><span>34% of observed activity</span></div><div><small>MOST TARGETED</small><b>ENG-WS-03</b><span>9 correlated detections</span></div></section><div className="report-grid"><section className="report-chart"><ZoneHead eyebrow="EVENT VOLUME" title="Telemetry velocity" status="8H"/><ResponsiveContainer width="100%" height={290}><AreaChart data={stats.events_over_time}><defs><linearGradient id="reportFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#48d9b0" stopOpacity=".32"/><stop offset="1" stopColor="#48d9b0" stopOpacity="0"/></linearGradient></defs><CartesianGrid stroke="#24372f" vertical={false}/><XAxis dataKey="time"/><YAxis/><Tooltip contentStyle={{background:'#0c1411',border:'1px solid #365045'}}/><Area dataKey="events" stroke="#4be0b7" fill="url(#reportFill)" strokeWidth={2}/></AreaChart></ResponsiveContainer></section><section className="report-chart"><ZoneHead eyebrow="AUTHENTICATION" title="Failure pattern" status="7D"/><ResponsiveContainer width="100%" height={290}><BarChart data={data.reports.auth_failures}><CartesianGrid stroke="#24372f" vertical={false}/><XAxis dataKey="day"/><YAxis/><Tooltip contentStyle={{background:'#0c1411',border:'1px solid #365045'}}/><Bar dataKey="failures" fill="#f3aa45" radius={[2,2,0,0]}/></BarChart></ResponsiveContainer></section></div></div>}
function riskScore(alert){
  const base={Critical:45,High:32,Medium:20,Low:8,Informational:3}[alert?.severity] ?? 10;
  const status=alert?.status==='New'?12:0;
  const behavior=/(failed|brute|malware|privilege|suspicious|unauthorized)/i.test(`${alert?.alert_type||''} ${alert?.detection_reason||''}`)?15:0;
  const source=alert?.source_ip?5:0;
  return Math.min(100,base+status+behavior+source);
}
function riskReasons(alert){
  const reasons=[`${alert?.severity||'Unknown'} severity contributes to the base score.`];
  if(alert?.status==='New') reasons.push('This alert is still new and has not been triaged.');
  if(/(failed|brute|malware|privilege|suspicious|unauthorized)/i.test(`${alert?.alert_type||''} ${alert?.detection_reason||''}`)) reasons.push('Detection text contains a higher-risk behavior indicator.');
  if(alert?.source_ip) reasons.push('A source address is available for investigation.');
  return reasons;
}
function ResponsePreview({alert,complete,ledger,onRun,onClose}){
  return <div className="drawer-backdrop" onMouseDown={onClose}>
    <section className="response-preview" role="dialog" aria-modal="true" aria-labelledby="response-preview-title" onMouseDown={e=>e.stopPropagation()}>
      <header><span className="response-icon"><Icons.ShieldCheck size={22}/></span><button onClick={onClose} aria-label="Close preview"><Icons.X size={18}/></button></header>
      <small className="response-eyebrow">GR GUARDRAIL / GUARDED RESPONSE</small>
      <h2 id="response-preview-title">Containment preview</h2>
      <p>Review the proposed workflow for <b>{alert.alert_type}</b> before taking any real action.</p>
      <div className="preview-risk"><span>EXPLAINABLE RISK</span><strong>{riskScore(alert)} / 100</strong><small>Alert ID: {alert.id} · Severity: {alert.severity}</small></div>
      <ol className="preview-steps">
        <li><Icons.CheckCircle2 size={16}/><span><b>Review alert context</b><small>Source: {alert.source_ip || 'Not recorded'} · Host: {alert.host || 'Not recorded'}</small></span></li>
        <li><Icons.ClipboardCheck size={16}/><span><b>Prepare response checklist</b><small>Confirm asset ownership, scope, and recovery path.</small></span></li>
        <li><Icons.LockKeyhole size={16}/><span><b>Require authorized approval</b><small>No firewall or process actions are connected to this preview.</small></span></li>
      </ol>
      {complete && <div className="dryrun-result"><Icons.CheckCircle2 size={17}/><span><b>Dry run recorded</b><small>No system commands executed; no host configuration changed.</small></span></div>}
      <button className="preview-primary" onClick={complete?onClose:onRun}>{complete?'CLOSE PREVIEW':'RUN SAFE DRY RUN'} <Icons.ArrowRight size={15}/></button>
      <p className="preview-disclaimer">Demo ledger is held in browser memory and clears when the page is refreshed. This is not a persistent audit log.</p>
      {ledger.length>0 && <section className="preview-ledger"><b>RECENT DRY RUNS · THIS SESSION</b>{ledger.slice(0,3).map(item=><p key={item.id}>#{item.alertId} · {item.alertType} · {new Date(item.timestamp).toLocaleTimeString()}</p>)}</section>}
    </section>
  </div>
}
function PageTitle({overline,title,text,count}){return <header className="page-title"><div><small>{overline}</small><h1>{title}</h1><p>{text}</p></div><span><i/>{count}</span></header>}
