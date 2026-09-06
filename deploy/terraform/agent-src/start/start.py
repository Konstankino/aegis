"""API front door for the agent stacks (API Gateway HTTP API → this Lambda).

Because a turn may pause for human approval, the request is asynchronous:
  * POST /chat    {message, thread_id?}  -> starts a Step Functions execution, returns its arn
  * GET  /status?executionArn=...        -> returns RUNNING / SUCCEEDED + the final answer

Wire your own auth (JWT authorizer / IAM) in front of this in production — it is unauthenticated
scaffolding. Standard library + boto3 only.
"""

import json
import os
import uuid

import boto3

STATE_MACHINE_ARN = os.environ["STATE_MACHINE_ARN"]
sfn = boto3.client("stepfunctions")


def _resp(status, body):
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body),
    }


def handler(event, context):
    # API Gateway HTTP API (payload v2) routing.
    method = event.get("requestContext", {}).get("http", {}).get("method", "GET")
    path = event.get("rawPath", "/")

    if method == "POST" and path.endswith("/chat"):
        body = json.loads(event.get("body") or "{}")
        message = body.get("message")
        if not message:
            return _resp(400, {"error": "missing 'message'"})
        thread_id = body.get("thread_id") or str(uuid.uuid4())
        execution = sfn.start_execution(
            stateMachineArn=STATE_MACHINE_ARN,
            input=json.dumps({"thread_id": thread_id, "input": message}),
        )
        return _resp(202, {"executionArn": execution["executionArn"], "thread_id": thread_id})

    if method == "GET" and path.endswith("/status"):
        arn = (event.get("queryStringParameters") or {}).get("executionArn")
        if not arn:
            return _resp(400, {"error": "missing 'executionArn'"})
        desc = sfn.describe_execution(executionArn=arn)
        out = {"status": desc["status"]}
        if desc["status"] == "SUCCEEDED" and desc.get("output"):
            out["result"] = json.loads(desc["output"])
        return _resp(200, out)

    return _resp(404, {"error": "not found", "path": path, "method": method})
