from . import clients

class CloudwatchLogReader:
    next_page_token = None

    def __init__(self, log_stream_name, head=None, tail=None, log_group_name="/aws/batch/job"):
        self.log_group_name = log_group_name
        self.log_stream_name = log_stream_name
        self.head, self.tail = head, tail
        self.next_page_key = "nextForwardToken" if self.tail is None else "nextBackwardToken"

    def __iter__(self):
        page = None
        get_args = dict(logGroupName=self.log_group_name, logStreamName=self.log_stream_name,
                        limit=min(self.head or 10000, self.tail or 10000))
        get_args["startFromHead"] = True if self.tail is None else False
        if self.next_page_token:
            get_args["nextToken"] = self.next_page_token
        while True:
            page = clients.logs.get_log_events(**get_args)
            for event in page["events"]:
                if "timestamp" in event and "message" in event:
                    yield event
            get_args["nextToken"] = page[self.next_page_key]
            if self.head is not None or self.tail is not None or len(page["events"]) == 0:
                break
        if page:
            CloudwatchLogReader.next_page_token = page[self.next_page_key]
