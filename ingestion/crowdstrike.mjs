import { FalconClient, FalconErrorExplain } from "crowdstrike-falcon";
import querystring from 'querystring';
import fetch from "node-fetch";
import * as dotenv from 'dotenv'
import argparse from 'argparse';
import fs from 'fs';
import zlib from 'zlib';


//
// INIT
//
dotenv.config()


const parser = new argparse.ArgumentParser({
  description: 'Script to query incidents and behaviors from CrowdStrike and send alerts to IRIS.'
});
parser.add_argument('--tags', { help: 'Comma-separated list of tags', required: true,  default:'crowdstrike,endpoint' });
parser.add_argument('--source', { help: 'Source of the alert', required: true, default:'crowdstrike' });
parser.add_argument('--cacheFolder', { help: 'Folder to use as Cache', default:'crowdstrike' });
parser.add_argument('--dryRun', { help: 'Run the script without sending alerts',  action: 'store_true' });
parser.add_argument('--status', { help: 'Status of the incidents to query (e.g., "open", "closed")', required: true });

const args = parser.parse_args();
const _SOURCE = args.source;
const _TAGS = args.tags;
const _CACHE_FOLDER=args.cacheFolder ?? _SOURCE;

const CROWDSTRIKE_CLIENT_ID = process.env.CROWDSTRIKE_CLIENT_ID
const CROWDSTRIKE_CLIENT_SECRET = process.env.CROWDSTRIKE_CLIENT_SECRET
const CROWDSTRIKE_CLIENT_REGION = process.env.CROWDSTRIKE_CLIENT_REGION

const IRIS_BASEURL = process.env.IRIS_BASEURL
const IRIS_API_KEY = process.env.IRIS_API_KEY
const IRIS_CUSTOMER_ID = process.env.IRIS_CUSTOMER_ID


//
// CROWDSTRIKE API
//

/* */
async function getToken(){
    const client = new FalconClient({
        cloud: `${CROWDSTRIKE_CLIENT_REGION}`,
        clientId: `${CROWDSTRIKE_CLIENT_ID}`,
        clientSecret: `${CROWDSTRIKE_CLIENT_SECRET}`,
    });
    const atoken= (await client.oauth2.oauth2AccessToken(CROWDSTRIKE_CLIENT_ID,CROWDSTRIKE_CLIENT_SECRET)).accessToken;
    return atoken;
}
/* */
async function queryIncidents(filter, sort){
    try{
        const postData={};
        if (filter){ postData['filter']=filter;}
        if (sort){ postData['sort']=sort;}
        const response = await fetch(`https://api.${CROWDSTRIKE_CLIENT_REGION}.crowdstrike.com/incidents/queries/incidents/v1?${querystring.stringify(postData)}`,{
            method:'GET',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${A_TOKEN}` 
              },
        });
        const data = await response.json();
        if (!response.ok) { console.log(`[!] Error: `,data?.errors); return null; }
        return data?.resources
    } catch (err){
        console.log(`[!] error:`,err)
    }
}
async function getIncidents(ids){
    try{
        const postData={};
        if (ids){ postData['ids']=ids;}

        const response = await fetch(`https://api.${CROWDSTRIKE_CLIENT_REGION}.crowdstrike.com/incidents/entities/incidents/GET/v1`,{
            method:'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${A_TOKEN}` 
              },
              body: JSON.stringify(postData)
        });
        const data = await response.json();
        if (!response.ok) { console.log(`[!] Error: `,data?.errors); return null; }
        return data?.resources
    } catch (err){
        console.log(`[!] error:`,err)
    }
}
async function queryIncidentBehaviors(filter, sort){
    try{
        const postData={};
        if (filter){ postData['filter']=filter;}
        if (sort){ postData['sort']=sort;}
        const response = await fetch(`https://api.${CROWDSTRIKE_CLIENT_REGION}.crowdstrike.com/incidents/queries/behaviors/v1?${querystring.stringify(postData)}`,{
            method:'GET',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${A_TOKEN}` 
              },
        });
        const data = await response.json();
        if (!response.ok) { console.log(`[!] Error: `,data?.errors); return null; }
        return data?.resources
    } catch (err){
        console.log(`[!] error:`,err)
    }
}
async function getIncidentBehaviors(ids){
    try{
        const postData={};
        if (ids){ postData['ids']=ids;}

        const response = await fetch(`https://api.${CROWDSTRIKE_CLIENT_REGION}.crowdstrike.com/incidents/entities/behaviors/GET/v1`,{
            method:'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${A_TOKEN}` 
              },
              body: JSON.stringify(postData)
        });
        const data = await response.json();
        if (!response.ok) { console.log(`[!] Error: `,data?.errors); return null; }
        return data?.resources
    } catch (err){
        console.log(`[!] error:`,err)
    }
}

//
// IRIS API
//

async function sendAlertToIris(title, text, source, options){

    let severity_id
    switch (true) {
    case options?.severity && ( ('string'===typeof(options?.severity)&&options?.severity.toLowerCase().startsWith('l') ) || ('number'===typeof(options?.severity) && options?.severity<4 ) ):
        // low
        severity_id=2;
        break;
    case options?.severity && ( ('string'===typeof(options?.severity)&&options?.severity.toLowerCase().startsWith('m') ) || ('number'===typeof(options?.severity) && options?.severity<7 ) ):
        // medium
        severity_id=4;
        break;
    case options?.severity && ( ('string'===typeof(options?.severity)&&options?.severity.toLowerCase().startsWith('h') ) || ('number'===typeof(options?.severity) && options?.severity<10 ) ):
        // medium
        severity_id=5;
        break;
    case options?.severity && ( ('string'===typeof(options?.severity)&&options?.severity.toLowerCase().startsWith('c') ) || ('number'===typeof(options?.severity) && options?.severity<10 ) ):
        // critical
        severity_id=6;
        break;
    default:
        // medium
        severity_id=4;
    };
    let iocs =options?.iocs??[]
    let assets =options?.assets??[]


    const payload={
        "alert_title": `${title}`,
        "alert_description": `${text}`,
        "alert_source": `${source}`,
        "alert_source_ref": `${options?.id??'N/A'}`,
        "alert_source_link": `${options?.link??'N/A'}`,
        "alert_source_content": options?.content??{},
        "alert_severity_id": severity_id,
        "alert_status_id": 3,
        "alert_context": {},
        "alert_source_event_time": `${new Date(options?.date??new Date()).toISOString()}`,
        "alert_note": `${options?.note??title}`,
        "alert_tags": `${options?.tags??''}`,
        "alert_iocs": iocs,
        "alert_assets": assets,
        "alert_customer_id": `${options?.customer_id??IRIS_CUSTOMER_ID}`,
        "alert_classification_id": 1
    };

    try{
        const response = await fetch(`${IRIS_BASEURL}alerts/add`,{
                method:'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${IRIS_API_KEY}` 
                  },
                  body: JSON.stringify(payload)
        });
        const data = await response.json();
        if (!response.ok) { console.log(`[!] Error: `,data);  }
    } catch (err){
        console.log(`[!] Error pushing alert "${title}":`,err)
    }

}

//
// CACHE
//
async function cacheGet(key){
    if (!fs.existsSync(_CACHE_FOLDER)) { fs.mkdirSync(_CACHE_FOLDER); }
    if (!fs.existsSync(`${_CACHE_FOLDER}/${key}`)){ return null; }

    const gunzip = zlib.createGunzip();
    const readStream = fs.createReadStream(`${_CACHE_FOLDER}/${key}`);
    const chunks = [];
    return new Promise((resolve,reject)=>{
        readStream
        .pipe(gunzip)
        .on('data', (chunk) => chunks.push(chunk))
        .on('end', () => {
            const content = Buffer.concat(chunks).toString();
            try{
                const jcontent=JSON.parse(content);
                resolve(jcontent)
            }catch (ex){
                console.error(`[!] Error parsing cached event "${key}"`,ex);
                resolve(null);
            }
        })
      .on('error', (err) => { console.error('[!] An error occurred:', err); resolve(null);});
    });
}
async function cacheSave(key,data){
    if (!fs.existsSync(_CACHE_FOLDER)) { fs.mkdirSync(_CACHE_FOLDER); }

    const gzip = zlib.createGzip();
    const writeStream = fs.createWriteStream(`${_CACHE_FOLDER}/${key}`);
    return new Promise((resolve, reject)=>{
        writeStream.on('finish', () => {  resolve(true); });
        writeStream.on('error', (err) => { console.error(`[!] Error caching ${key}`,err);  resolve(false); });
        
        gzip.write(data);
        gzip.pipe(writeStream);
        gzip.end();
    });

}

//
// MISC
//

function summarizeJSON(data){
    const simplifiedData = {
  dateOfIncident: data.created,
  status: data.state,
  tactics: data.tactics.join(', '),
  objectives: data.objectives.join(', '),
  usersInvolved: data.users,
  hosts: data.hosts.map(host => ({
    deviceId: host.device_id,
    externalIp: host.external_ip,
    hostname: host.hostname,
    lastLoginUser: host.last_login_user,
    status: host.status
  })),
  behaviors: data.behaviors.map(behavior => ({
    dateOfEvidence: behavior.timestamp,
    userName: behavior.user_name,
    tacticId: behavior.tactic_id,
    sha256: behavior.sha256,
    cmdline: behavior.cmdline
  })),  
};
 return simplifiedData;
}
function toText(data){
    return `
Date of Incident: ${data.dateOfIncident}
Status: ${data.status}
Users Involved: ${data.usersInvolved}
Tactics: ${data.tactics}

# Hosts Involved:
${data.hosts.map(host => `  Hostname: ${host.hostname}, IP: ${host.externalIp}, User: ${host.lastLoginUser}, Status: ${host.status}`).join('\n')}

# Behaviors Evidence:
${data.behaviors.map(behavior => `  Date: ${behavior.dateOfEvidence}, User: ${behavior.userName}, Tactic ID: ${behavior.tacticId}, SHA-256: ${behavior.sha256}, Command Line: ${behavior.cmdline}`).join('\n')}
`;
// https://falcon.crowdstrike.com/activity/detections/detail/<<REPLACE(REPLACE(behavior.explode_behaviors.individual_behavior.control_graph_id, "ctg:", ""), ":", "/")>>
}



//
// MAIN
//

const A_TOKEN = await getToken();
let inc_ids = await queryIncidents(`state:"${args.status??'open'}"`,'start|desc');
if (!inc_ids||inc_ids.length==0){ console.log(`[+] no incidents retrieved`);process.exit(0);}

for (let i=0;i<inc_ids.length;i++){
    let key=inc_ids[i]
    let cached=await cacheGet(key);
    if (cached){ const idx=inc_ids.indexOf(key); inc_ids.splice(idx,1); }
}


let incidents=await getIncidents(inc_ids)
let ib_ids=await queryIncidentBehaviors(`${incidents.map(i=>`incident_ids:"${i.incident_id}"`).join(',')} `)
let ibs=await getIncidentBehaviors(ib_ids)


incidents.forEach(incident=>{
    incident.behaviors=[];
    ibs.forEach(ib=>{ if ( ib.incident_ids.indexOf(incident.incident_id)!=-1){ incident.behaviors.push(ib); } })
});

const s_inc=incidents.map(summarizeJSON);

for (let i=0;i<s_inc.length;i++){

    const _text=toText(s_inc[i]);
    const _title=`CrowdStrike: ${s_inc[i].tactics} - ${s_inc[i].hosts.map(x=>x.hostname)}`
    const _date=s_inc[i].dateOfIncident
    const _assets=s_inc[i].hosts.map(h=>{
        return { asset_name: h.hostname, asset_description: "", asset_type_id: 1, asset_ip: "", asset_domain: "", asset_tags: "", asset_enrichment: {} };
    });
    const _iocs=s_inc[i].behaviors.map(h=>{
        return { ioc_value: "", ioc_description: "", ioc_tlp_id: 1, ioc_type_id: 2, ioc_tags: "", ioc_enrichment: {}};
    });
    console.log(`[+] pushing alert for incident (${_title})`)
    if (!args.dryRun){ 
        await sendAlertToIris(_title, _text, _SOURCE, { date:_date, severity:'medium', assets:_assets ,tags:_TAGS});
    } else{
        console.log(`[-] incident raw data:`,s_inc[i])        
    }
}
