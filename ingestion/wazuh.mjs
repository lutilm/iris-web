#!/usr/bin/env nodejs
import fetch from 'node-fetch';
import dotenv from 'dotenv';
import fs from 'fs';
import { ArgumentParser } from 'argparse';
import https from 'https';

const httpsAgent = new https.Agent({
    rejectUnauthorized: false, // WARNING: This bypasses SSL certificate validation. Use with caution.
  });
/*
Add the following snippet into the /var/ossec/etc/ossec.conf config file:

<!-- ... Rest of config ... -->

<!-- IRIS integration -->
<integration>
  <name>wazuh.mjs</name>
  <hook_url>http://IRIS-BASE-URL/alerts/add</hook_url>
  <level>7</level>
  <api_key>APIKEY</api_key>
  <options>{"customer_id": CUSTOMERID}</options> 
  <alert_format>json</alert_format>
</integration>

<!-- ... Rest of config ... -->
*/

// Initialize dotenv
dotenv.config();

const _SOURCE='wazuh'
const _TAGS='wazuh'

const WAZUH_BASEURL = process.env.WAZUH_BASEURL 
const IRIS_BASEURL = process.env.IRIS_BASEURL
const IRIS_API_KEY = process.env.IRIS_API_KEY
const IRIS_CUSTOMER_ID = process.env.IRIS_CUSTOMER_ID

// Function to create a formatted string from alert details
function formatAlertDetails(alertJson) {
    const rule = alertJson.rule || {};
    const agent = alertJson.agent || {};
    const mitre = rule.mitre || {};
    const mitreIds = (mitre.id || ["N/A"]).join(', ');
    const mitreTactics = (mitre.tactic || ["N/A"]).join(', ');
    const mitreTechniques = (mitre.technique || ["N/A"]).join(', ');

    const details = [
        `Rule ID: ${rule.id || 'N/A'}`,
        `Rule Level: ${rule.level || 'N/A'}`,
        `Rule Description: ${rule.description || 'N/A'}`,
        `Agent ID: ${agent.id || 'N/A'}`,
        `Agent Name: ${agent.name || 'N/A'}`,
        `MITRE IDs: ${mitreIds}`,
        `MITRE Tactics: ${mitreTactics}`,
        `MITRE Techniques: ${mitreTechniques}`,
        `Location: ${alertJson.location || 'N/A'}`,
        `Full Log: ${alertJson.full_log || 'N/A'}`
    ];
    return details.join('\n');
}

// Main function to process the alert
async function processAlert(alertFile, apiKey, baseUrl, irisCustomerId) {
    // Read the alert file
    const alertJson = JSON.parse(fs.readFileSync(alertFile, 'utf8'));
    const alertDetails = formatAlertDetails(alertJson);

    // Convert Wazuh rule levels(0-15) -> IRIS severity(1-6)
    const alertLevel = alertJson.rule?.level || 0;
    let severity;
    if(alertLevel < 5) severity = 2;
    else if(alertLevel >= 5 && alertLevel < 7) severity = 3;
    else if(alertLevel >= 7 && alertLevel < 10) severity = 4;
    else if(alertLevel >= 10 && alertLevel < 13) severity = 5;
    else if(alertLevel >= 13) severity = 6;
    else severity = 1;

    const payload = {
        alert_title: alertJson.rule?.description || "No Description",
        alert_description: alertDetails,
        alert_source: _SOURCE,
        alert_source_ref: alertJson.id || "Unknown ID",
        alert_source_link: `${WAZUH_BASEURL}`,  // Replace with actual Wazuh URL
        alert_severity_id: severity,
        alert_status_id: 2,  // 'New' status
        alert_source_event_time: alertJson.timestamp || "Unknown Timestamp",
        alert_note: "",
        alert_tags: _TAGS,//`wazuh,${alertJson.agent?.name || 'N/A'}`,
        alert_customer_id: irisCustomerId??alertJson.customer_id??IRIS_CUSTOMER_ID,  // '1' for default 'IrisInitialClient'
        alert_source_content: alertJson  // raw log
    };

    const response = await fetch( `${baseUrl??IRIS_BASEURL}alerts/add`, {
        method: 'POST',
        agent: httpsAgent,
        headers: {
            "Authorization": `Bearer ${apiKey??IRIS_API_KEY}`,
            "Content-Type": "application/json"
        },
        body: JSON.stringify(payload)
    });

    if (!response.ok) {
        const errorText = await response.text();
        console.error(`Failed to send alert: ${errorText}`);
    } else {
        console.log("Alert sent successfully");
    }
}

parser.add_argument('file', { help: 'Alert JSON file', required: true });
parser.add_argument('irisApiKey', { help: 'iris api key', required: true });
parser.add_argument('irisBaseUrl', { help: 'iris base url', required: true });
parser.add_argument('irisCustomerId', { help: 'iris customer id', required: false });
const args = parser.parse_args();

processAlert(args.file,args.irisApiKey,args.irisBaseUrl, args.irisCustomerId);