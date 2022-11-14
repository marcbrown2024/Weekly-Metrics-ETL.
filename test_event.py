# import the required libraries

from weekly_metrics_collector import run
import time

# -----------------------------------------------------------------------------------

# MAIN PROGRAM EVENT TESTING

start = time.time()
test_event = {
    "Records": [
        {
            "eventVersion": "2.0",
            "eventSource": "aws:s3",
            "awsRegion": "us-east-1",
            "eventTime": "1970-01-01T00:00:00.000Z",
            "eventName": "ObjectCreated:Put",
            "userIdentity": {
                "principalId": "EXAMPLE"
            },
            "requestParameters": {
                "sourceIPAddress": "127.0.0.1"
            },
            "responseElements": {
                "x-amz-request-id": "EXAMPLE123456789",
                "x-amz-id-2": "EXAMPLE123/5678abcdefghijklambdaisawesome/mnopqrstuvwxyzABCDEFGH"
            },
            "s3": {
                "s3SchemaVersion": "1.0",
                "configurationId": "testConfigRule",
                "bucket": {
                    "name": "weekly-epo-metrics",
                    "arn": "arn:aws:s3:::weekly-epo-metrics"
                },
                "object": {
                    "key": "clbrjcn2rmm89o49nfbrim6v37s4cl13nb7lqoo1"
                }
            }
        }
    ]
}

run(test_event, None)
end = time.time()
print(end - start)

# -----------------------------------------------------------------------------------
