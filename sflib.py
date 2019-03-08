# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sflib
# Purpose:      Common functions used by SpiderFoot modules.
#               Also defines the SpiderFootPlugin abstract class for modules.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     26/03/2012
# Copyright:   (c) Steve Micallef 2012
# Licence:     GPL
# -------------------------------------------------------------------------------
import gzip
import hashlib
from io import StringIO
import netaddr
import os
import random
import re
import sys
import time
import urllib

import requests


def unicode(text, *args, **kwargs):
    return text


class SpiderFoot:
    def __init__(self):
        self.results = list()

    def clear_results(self):
        self.results = list()

    def get_results(self):
        return self.results

    def save_result(self, event):
        self.results.append(event)

    def _print(self, *args):
        print(*args)

    def debug(self, *args):
        self._print("DEBUG", *args)

    def info(self, *args):
        self._print("INFO", args)

    def error(self, *args):
        self._print("ERROR", *args)

    def fatal(self, *args):
        self._print("FATAL", *args)

    def urlEncodeUnicode(self, url):
        return re.sub('[\x80-\xFF]', lambda c: '%%%02x' % ord(c.group(0)), url)

    def hashstring(self, string):
        s = string
        if type(string) in [list, dict]:
            s = str(string)
        return hashlib.sha256(s.encode('raw_unicode_escape')).hexdigest()

    # Simple way to verify IPs.
    def validIP(self, address):
        return netaddr.valid_ipv4(address)

    #
    # Caching
    #

    # Return the cache path
    def cachePath(self):
        path = self.myPath() + '/cache'
        if not os.path.isdir(path):
            os.mkdir(path)
        return path

    # Store data to the cache
    def cachePut(self, label, data):
        return None

    # Retreive data from the cache
    def cacheGet(self, label, timeoutHrs):
        return None

    # Fetch a URL, return the response object
    def fetchUrl(self, url, fatal=False, cookies=None, timeout=30,
                 useragent="SpiderFoot", headers=None, noLog=False,
                 postData=None, dontMangle=False, sizeLimit=None,
                 headOnly=False):
        result = {
            'code': None,
            'status': None,
            'content': None,
            'headers': None,
            'realurl': url
        }

        if url is None:
            return None

        # Clean the URL
        if type(url) != str:
            url = str(url)

        # Convert any unicode chars in the URL
        url = str(self.urlEncodeUnicode(url))

        try:
            header = dict()
            if type(useragent) is list:
                header['User-Agent'] = random.choice(useragent)
            else:
                header['User-Agent'] = useragent

            # Add custom headers
            if headers is not None:
                for k in headers.keys():
                    header[k] = headers[k]

            if sizeLimit or headOnly:
                if not noLog:
                    self.info("Fetching (HEAD only): " + url + \
                          " [timeout: " + \
                          str(timeout) + "]")

                hdr = requests.head(url, headers=header, verify=False, timeout=timeout)
                size = int(hdr.headers.get('content-length', 0))
                result['realurl'] = hdr.headers.get('location', url)
                result['code'] = str(hdr.status_code)

                if headOnly:
                    return result

                if size > sizeLimit:
                    return result

                if result['realurl'] != url:
                    if not noLog:
                       self.info("Fetching (HEAD only): " + url + \
                              " [timeout: " + \
                              str(timeout) + "]")

                    hdr = requests.head(result['realurl'], headers=header, verify=False)
                    size = int(hdr.headers.get('content-length', 0))
                    result['realurl'] = hdr.headers.get('location', result['realurl'])
                    result['code'] = str(hdr.status_code)

                    if size > sizeLimit:
                        return result

            req = urllib.request.Request(url, postData, header)
            if cookies is not None:
                req.add_header('cookie', cookies)
                if not noLog:
                    self.info("Fetching (incl. cookies): " + url + \
                          " [timeout: " + \
                          str(timeout) + "]")
            else:
                if not noLog:
                    self.info("Fetching: " + url + " [timeout: " + str(timeout) + "]")

            result['headers'] = dict()
            opener = urllib.request.build_opener(SmartRedirectHandler())
            fullPage = opener.open(req, timeout=timeout)
            content = fullPage.read()

            for k, v in fullPage.info().items():
                result['headers'][k.lower()] = v

            # Content is compressed
            if 'gzip' in result['headers'].get('content-encoding', ''):
                content = gzip.GzipFile(fileobj=StringIO(content)).read()

            if dontMangle:
                result['content'] = content
            else:
                result['content'] = str(content)

            result['realurl'] = fullPage.geturl()
            result['code'] = str(fullPage.getcode())
            result['status'] = 'OK'
        except urllib.request.HTTPError as h:
            if not noLog:
                self.info("HTTP code " + str(h.code) + " encountered for " + url)
            # Capture the HTTP error code
            result['code'] = str(h.code)
            for k, v in h.info().items():
                result['headers'][k.lower()] = v
            if fatal:
                self.fatal('URL could not be fetched (' + str(h.code) + ')')
        except urllib.request.URLError as e:
            if not noLog:
                self.info("Error fetching " + url + "(" + str(e) + ")")
            result['status'] = str(e)
            if fatal:
                self.fatal('URL could not be fetched (' + str(e) + ')')
        except Exception as x:
            if not noLog:
                self.info("Unexpected exception occurred fetching: " + url + " (" + str(x) + ")")
            result['content'] = None
            result['status'] = str(x)
            if fatal:
                self.fatal('URL could not be fetched (' + str(x) + ')')

        return result


# Override the default redirectors to re-use cookies
class SmartRedirectHandler(urllib.request.HTTPRedirectHandler):
    def http_error_301(self, req, fp, code, msg, headers):
        if "Set-Cookie" in headers:
            req.add_header('cookie', headers['Set-Cookie'])
        result = urllib.request.HTTPRedirectHandler.http_error_301(
            self, req, fp, code, msg, headers)
        return result

    def http_error_302(self, req, fp, code, msg, headers):
        if "Set-Cookie" in headers:
            req.add_header('cookie', headers['Set-Cookie'])
        result = urllib.request.HTTPRedirectHandler.http_error_302(
            self, req, fp, code, msg, headers)
        return result


class SpiderFootPlugin:
    # Will be set to True by the controller if the user aborts scanning
    _stopScanning = False
    # Modules that will be notified when this module produces events
    _listenerModules = list()
    # Current event being processed
    _currentEvent = None
    # Target currently being acted against
    _currentTarget = None
    # Name of this module, set at startup time
    __name__ = "module_name_not_set!"
    # Direct handle to the database - not to be directly used
    # by modules except the sfp__stor_db module.
    __sfdb__ = None
    # ID of the scan the module is running against
    __scanId__ = None
    # (Unused) tracking of data sources
    __dataSource__ = None
    # If set, events not matching this list are dropped
    __outputFilter__ = None

    # Not really needed in most cases.
    def __init__(self):
        pass

    # Hack to override module's use of socket, replacing it with
    # one that uses the supplied SOCKS server
    def _updateSocket(self, sock):
        socket = sock
        #urllib2.socket = sock

    # Used to clear any listener relationships, etc. This is needed because
    # Python seems to cache local variables even between threads.
    def clearListeners(self):
        self._listenerModules = list()
        self._stopScanning = False

    # Will always be overriden by the implementer.
    def setup(self, sf, userOpts=dict()):
        pass

    # Hardly used, only in special cases where a module can find
    # aliases for a target.
    def enrichTarget(self, target):
        pass

    # Assigns the current target this module is acting against
    def setTarget(self, target):
        self._currentTarget = target

    # Used to set the database handle, which is only to be used
    # by modules in very rare/exceptional cases (e.g. sfp__stor_db)
    def setDbh(self, dbh):
        self.__sfdb__ = dbh

    # Set the scan ID
    def setScanId(self, id):
        self.__scanId__ = id

    # Get the scan ID
    def getScanId(self):
        return self.__scanId__

    # Gets the current target this module is acting against
    def getTarget(self):
        if self._currentTarget is None:
            print("Internal Error: Module called getTarget() but no target set.")
            sys.exit(-1)
        return self._currentTarget

    # Listener modules which will get notified once we have data for them to
    # work with.
    def registerListener(self, listener):
        self._listenerModules.append(listener)

    def setOutputFilter(self, types):
        self.__outputFilter__ = types

    def notifyListeners(self, sfEvent):
        if self.checkForStop():
            return None

        self.sf.save_result(sfEvent.asDict())

    # For modules to use to check for when they should give back control
    def checkForStop(self):
        return False

    # Return a list of the default configuration options for the module.
    def defaultOpts(self):
        return self.opts

    # What events is this module interested in for input. The format is a list
    # of event types that are applied to event types that this module wants to
    # be notified of, or * if it wants everything.
    # Will usually be overriden by the implementer, unless it is interested
    # in all events (default behavior).
    def watchedEvents(self):
        return ['*']

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return None

    # Handle events to this module
    # Will usually be overriden by the implementer, unless it doesn't handle
    # any events.
    def handleEvent(self, sfEvent):
        return None

    # Kick off the work (for some modules nothing will happen here, but instead
    # the work will start from the handleEvent() method.
    # Will usually be overriden by the implementer.
    def start(self):
        return None


class SpiderFootEvent:
    generated = None
    eventType = None
    confidence = None
    visibility = None
    risk = None
    module = None
    data = None
    sourceEvent = None
    sourceEventHash = None
    moduleDataSource = None
    __id = None

    def __init__(self, eventType, data, module, sourceEvent,
                 confidence=100, visibility=100, risk=0):
        self.eventType = eventType
        self.generated = time.time()
        self.confidence = confidence
        self.visibility = visibility
        self.risk = risk
        self.module = module
        self.sourceEvent = sourceEvent

        if type(data) in [list, dict]:
            print("FATAL: Only string events are accepted, not lists or dicts.")
            print("FATAL: Offending module: " + module)
            print("FATAL: Offending type: " + eventType)
            sys.exit(-1)

        if type(data) != str and data != None:
            self.data = str(data)
        else:
            self.data = data

        # "ROOT" is a special "hash" reserved for elements with no
        # actual parent (e.g. the first page spidered.)
        if eventType == "ROOT":
            self.sourceEventHash = "ROOT"
            return

        self.sourceEventHash = sourceEvent.getHash()
        self.__id = self.eventType + str(self.generated) + self.module + \
            str(random.randint(0, 99999999))

    def asDict(self):
        return {
            'generated': int(self.generated),
            'type': self.eventType,
            'data': self.data,
            'module': self.module,
            'source': self.sourceEvent.data
        }

    # Unique hash of this event
    def getHash(self):
        if self.eventType == "ROOT":
            return "ROOT"
        digestStr = self.__id.encode('raw_unicode_escape')
        return hashlib.sha256(digestStr).hexdigest()

    # Update variables as new information becomes available
    def setConfidence(self, confidence):
        self.confidence = confidence

    def setVisibility(self, visibility):
        self.visibility = visibility

    def setRisk(self, risk):
        self.risk = risk

    def setSourceEventHash(self, srcHash):
        self.sourceEventHash = srcHash
