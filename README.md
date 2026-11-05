# Phishing detector on AWS

A rule-based email phishing detector (command line and web UI) and the Terraform that deploys it on AWS:
two EC2 instances behind an Application Load Balancer, with scan history in Amazon RDS.

> This README is an outline; each section is filled in as the corresponding part is built.

## What it does

_Input formats, the indicator families, how the risk score and verdict are computed, example output._

## Architecture

_Diagram and request flow: CloudFront, ALB, Auto Scaling group of two EC2 instances, RDS PostgreSQL, ElastiCache, logging and monitoring._

## Repository layout

_What lives where._

## Run locally

_Command-line scan without Docker; the web app with docker compose; running the tests._

## Deploy to AWS

_Prerequisites and tool versions, the two Terraform stacks and the order to apply them, setting the access secret, building and pushing the image._

## Invoke

_Using the web UI and the HTTP API on the deployed stack._

## Monitor

_Dashboard, alarms, where the application logs are, and how to check instance health, CPU and memory, request counts and errors._

## Tear down

_`terraform destroy` order and the CLI checks that confirm nothing is left._

## Cost

_What each resource costs per day and the total for the test period._

## Security

_IAM, network exposure, encryption, secrets handling, untrusted email handling, and the justification for every wildcard permission and every skipped scanner check._

## Assumptions

_How ambiguous points in the assignment were interpreted._

## Limitations

_What the detector and the infrastructure do not cover._

## Data sets

_Source and license of every data set used for testing and evaluation._

## Next steps

_What would come next with more time._
