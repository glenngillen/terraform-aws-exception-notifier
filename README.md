# Exceptions Notifier for AWS CloudWatch

If you've used one of the numerous exception tracking services out
there you probably have a certain set of expectations around how/when
you're notified if something goes wrong with your app. If you're all-in
on AWS though, and sending your events to CloudWatch, you don't get
any notifications out of the box.

This Terraform Module will send you an email alert any time it detects
a specific filter pattern (it defaults to `?ERROR ?WARN ?5xx`) in a 
CloudWatch log group.

## Usage

```hcl
module "agents" {
  source            = "glenngillen/exception-notifier/module"
  version           = "1.0.0"

  monitored-log-group-names = [
     "/aws/lambda/my-function",
     "/aws/lambda/another-function",
     "/aws/lambda/etc"
  ]
}
```