import { FalconClient, FalconErrorExplain } from "crowdstrike-falcon";
import querystring from 'querystring';
import fetch from "node-fetch";

import * as dotenv from 'dotenv'
dotenv.config()

const CROWDSTRIKE_CLIENT_ID = process.env.CROWDSTRIKE_CLIENT_ID
const CROWDSTRIKE_CLIENT_SECRET = process.env.CROWDSTRIKE_CLIENT_SECRET
const CROWDSTRIKE_CLIENT_REGION = process.env.CROWDSTRIKE_CLIENT_REGION
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
              //body: JSON.stringify(postData)
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
              //body: JSON.stringify(postData)
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
/// MAIN

const A_TOKEN = await getToken();


let inc_ids = await queryIncidents('state:"closed"','start|desc');

let incidents=await getIncidents(inc_ids)


let ib_ids=await queryIncidentBehaviors(`incident_ids:"${incidents[0].incident_id}"`)

//console.log(incidents[0],incidents[0].incident_id,ib_ids)


let ibs=await getIncidentBehaviors(ib_ids)
console.log('incidents')
console.log(incidents.map(x=>x.incident_id))
console.log('behaviors')
console.log(ibs.map(x=>(x.incident_ids)))
