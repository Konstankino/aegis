"""Auto-approver (demo): SQS-triggered, resumes a waitForTaskToken pause with SendTaskSuccess.

Replace with a real human approval UI (email/Slack) in production, or set auto_approve=false and
approve manually:  aws stepfunctions send-task-success --task-token <token> --task-output '{"ok":true}'
"""

import json
import os

import boto3

sfn = boto3.client("stepfunctions")
APPROVE = os.environ.get("AEGIS_AUTO_DECISION", "approve") == "approve"


def handler(event, context):
    handled = 0
    for record in event.get("Records", []):
        body = json.loads(record["body"])
        token = body["taskToken"]
        if APPROVE:
            sfn.send_task_success(taskToken=token, output=json.dumps({"approved": True}))
        else:
            sfn.send_task_failure(taskToken=token, error="HumanRejected", cause="auto-approver rejects")
        handled += 1
    return {"handled": handled}
