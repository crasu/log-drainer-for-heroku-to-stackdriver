import json
import time
import logging
import google.cloud.logging
import iso8601
from base64 import b64decode
from pyparsing import Word, Suppress, nums, Optional, Regex, pyparsing_common, alphanums
from syslog import LOG_DEBUG, LOG_WARNING, LOG_INFO, LOG_NOTICE
from collections import defaultdict
from datetime import datetime

client = google.cloud.logging.Client()
logger = client.logger('heroku-log')

class Parser(object):
    def __init__(self):
        ints = Word(nums)

        # priority
        priority = Suppress("<") + ints + Suppress(">")

        # version
        version = ints

        # timestamp
        timestamp = pyparsing_common.iso8601_datetime

        # hostname
        hostname = Word(alphanums + "_" + "-" + ".")

        # source
        source = Word(alphanums + "_" + "-" + ".")

        # appname
        appname = Word(alphanums + "(" + ")" + "/" + "-" + "_" + ".") + Optional(Suppress("[") + ints + Suppress("]")) + Suppress("-")

        # message
        message = Regex(".*")

        # pattern build
        self.__pattern = priority + version + timestamp + hostname + source + appname + message

    def parse(self, line):
        parsed = self.__pattern.parseString(line)

        # https://tools.ietf.org/html/rfc5424#section-6
        # get priority/severity
        priority = int(parsed[0])
        severity = priority & 0x07
        facility = priority >> 3

        payload              = {}
        payload["priority"]  = priority
        payload["severity"]  = severity
        payload["facility"]  = facility
        payload["version"]   = parsed[1]
        payload["timestamp"] = iso8601.parse_date(parsed[2])
        payload["hostname"]  = parsed[3]
        payload["source"]    = parsed[4]
        payload["appname"]   = parsed[5]
        payload["message"]   = parsed[6]

        return payload

parser = Parser()


def stackdriver_handler(event):
    print("Received event: {} content type: {}".format(str(event), event.content_type))
    try: 
        handle_event(event)
    except Exception as e:
        print("Exception when handling: {}".format(event.data))
        raise e


# split into chunks
def get_chunk(payload):
    msg_len, syslog_msg_payload = payload.split(' ', maxsplit=1)
    msg_len = int(msg_len)

    # only grab msg_len bytes of syslog_msg
    syslog_msg = syslog_msg_payload[0:msg_len]
    next_payload = syslog_msg_payload[msg_len:]

    yield syslog_msg

    if next_payload:
        yield from get_chunk(next_payload)


def handle_event(event):
    body = event.data.decode('UTF-8')
    headers = event.headers

    # sanity-check source
    assert headers['X-Forwarded-Proto'] == 'https'
    assert headers['Content-Type'] == 'application/logplex-1'

    chunk_count = 0
    for chunk in get_chunk(body):
        evt = parser.parse(chunk)
        logger.log_struct({"message": str(evt["message"])}, timestamp=evt["timestamp"])

