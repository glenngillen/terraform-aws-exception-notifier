data "aws_caller_identity" "exception" {}
data "aws_region" "exception" {}
data "aws_partition" "exception" {}

locals {
  lambda_logs = format("arn:%v:logs:%v:%v:log-group:/aws/lambda/%v:*", data.aws_partition.exception.partition, data.aws_region.exception.name, data.aws_caller_identity.exception.account_id, var.function-name)
}

resource "aws_sns_topic" "exceptions" {
  name = "exceptions"
}

resource "aws_sns_topic_subscription" "exception-email" {
  topic_arn = aws_sns_topic.exceptions.arn
  protocol  = "email"
  endpoint  = var.notification-recipient-email
}

resource "aws_iam_role" "exception-handler" {
  name = "exception-handler"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}
resource "aws_iam_role_policy" "exception-handler-publish" {
  name = "exception-handler-publish"
  role = aws_iam_role.exception-handler.id
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "sns:Publish",
            "Resource": "${aws_sns_topic.exceptions.arn}"
        },
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": "${local.lambda_logs}"
        }
    ]
}
EOF
}

data "archive_file" "exception-zip" {
    type = "zip"
    output_path = "/tmp/exception-zip.zip"
    source {
        content  = <<EOF
# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at## http://aws.amazon.com/apache2.0/
# or in the "license" file accompanying this file.
# This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
# Description: This Lambda function sends an email notification to a given AWS SNS topic when a particular
#              pattern is matched in the logs of a selected Lambda function. The email subject is
#              Execution error for Lambda-<insert Lambda function name>.
#              The JSON message body of the SNS notification contains the full event details.

# Author: Sudhanshu Malhotra

import base64
import boto3
import gzip
import json
import logging
import os

from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def logpayload(event):
    logger.setLevel(logging.WARN)
    logger.debug(event['awslogs']['data'])
    compressed_payload = base64.b64decode(event['awslogs']['data'])
    uncompressed_payload = gzip.decompress(compressed_payload)
    log_payload = json.loads(uncompressed_payload)
    return log_payload


def error_details(payload):
    error_msg = ""
    log_events = payload['logEvents']
    logger.debug(payload)
    loggroup = payload['logGroup']
    logstream = payload['logStream']
    lambda_func_name = loggroup.split('/')
    logger.debug(f'LogGroup: {loggroup}')
    logger.debug(f'Logstream: {logstream}')
    logger.debug(f'Function name: {lambda_func_name[3]}')
    logger.debug(log_events)
    for log_event in log_events:
        error_msg += log_event['message']
    logger.debug('Message: %s' % error_msg.split("\n"))
    return loggroup, logstream, error_msg, lambda_func_name


def publish_message(loggroup, logstream, error_msg, lambda_func_name):
    sns_arn = os.environ['snsARN']  # Getting the SNS Topic ARN passed in by the environment variables.
    snsclient = boto3.client('sns')
    try:
        message = ""
        message += "\nLambda error  summary" + "\n\n"
        message += "##########################################################\n"
        message += "# LogGroup Name:- " + str(loggroup) + "\n"
        message += "# LogStream:- " + str(logstream) + "\n"
        message += "# Log Message:- " + "\n"
        message += "# \t\t" + str(error_msg.split("\n")) + "\n"
        message += "##########################################################\n"

        # Sending the notification...
        snsclient.publish(
            TargetArn=sns_arn,
            Subject=f'Execution error for Lambda - {lambda_func_name[3]}',
            Message=message
        )
    except ClientError as e:
        logger.error("An error occured: %s" % e)


def lambda_handler(event, context):
    pload = logpayload(event)
    lgroup, lstream, errmessage, lambdaname = error_details(pload)
    publish_message(lgroup, lstream, errmessage, lambdaname)
EOF
    filename = "handler.py"
  }
}
resource "aws_lambda_function" "exception-notifier" {
  function_name = "exception-notifier"
  role = aws_iam_role.exception-handler.arn
  handler = "handler.lambda_handler"
  runtime = "python3.8"
  timeout = 15
  environment {
    variables ={
        snsARN = aws_sns_topic.exceptions.arn
    }
  }

  filename         = "${data.archive_file.exception-zip.output_path}"
  source_code_hash = "${data.archive_file.exception-zip.output_base64sha256}"
}


data "aws_cloudwatch_log_group" "monitored-log-group" {
  for_each        = var.monitored-log-groups
  name            = each.value
}
resource "aws_lambda_permission" "exception-notifier-allow-cloudwatch" {
  for_each      = var.monitored-log-groups
  statement_id  = "exception-notifier-allow-cloudwatch-${element(split("/", each.value), length(split("/", each.value))-1)}"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.exception-notifier.arn}"
  principal     = format("logs.%v.amazonaws.com", data.aws_region.exception.name)
  source_arn    = "${data.aws_cloudwatch_log_group.monitored-log-group[each.value].arn}"
}
resource "aws_cloudwatch_log_subscription_filter" "exception-log-filter" {
  depends_on      = [aws_lambda_permission.exception-notifier-allow-cloudwatch]
  for_each        = var.monitored-log-groups
  name            = each.value
  log_group_name  = each.value
  filter_pattern  = var.cloudwatch-filter-pattern
  destination_arn = aws_lambda_function.exception-notifier.arn
}