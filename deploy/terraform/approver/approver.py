"""Auto-approver Lambda (demo convenience).

Triggered by the approval SQS queue. For each pending approval it reads the task token that the
Step Functions .waitForTaskToken task deposited and calls SendTaskSuccess to resume the paused
execution. In a real system this is where a HUMAN decides: replace this with an email/Slack
approval UI, or set var.auto_approve = false and approve manually with:

    aws stepfunctions send-task-success --task-token <token> --task-output '{"approved":true}'

The task token arrives in the SQS message body that the state machine wrote.
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
        tool_call = body.get("toolCall")
        if APPROVE:
            sfn.send_task_success(
                taskToken=token,
                output=json.dumps({"approved": True, "by": "auto-approver", "toolCall": tool_call}),
            )
        else:
            sfn.send_task_failure(
                taskToken=token, error="HumanRejected", cause="auto-approver configured to reject"
            )
        handled += 1
    return {"handled": handled}
