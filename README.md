# Dovetail CDN Log Shipper

Watches for CloudFront [standard logs](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/AccessLogs.html) (access logs) in S3, process them (primarily anonymizing IP addresses), and sending them an external destination (like a third-party's S3 bucket).

## Deployment

**Staging:**

```sh
sam build && sam deploy
```
**Production:**

```sh
sam build && sam deploy --config-env=prod
```
