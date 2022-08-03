# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sflib
# Purpose:      Common functions used by SpiderFoot modules.
#               Also defines the SpiderFootPlugin abstract class for modules.
#
# Author:      Steve Micallef <steve@binarypool.com>
# Modified:    Ajoy Oommen <ajoyoommen@gmail.com>
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

from bs4 import BeautifulSoup, SoupStrainer
import requests

if os.getenv('HTTPS_PROXY_SPIDERFOOT') != None:  
    https_proxy = os.getenv('HTTPS_PROXY_SPIDERFOOT')
    proxies = {
       'https': "http://"+https_proxy,
    }
else:
    proxies = None
print("Proxies in Spiderfoot", proxies)


def unicode(text, *args, **kwargs):
    return text


class SpiderFoot:
    def __init__(self):
        self.results = list()
        self._cache = {}

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

    # Clean DNS results to be a simple list
    def normalizeDNS(self, res):
        ret = list()
        for addr in res:
            if type(addr) == list:
                for host in addr:
                    ret.append(str(host))
            else:
                ret.append(str(addr))
        return ret

    #
    # Caching
    #

    # Store data to the cache
    def cachePut(self, label, data):
        if type(data) is list:
            data = '\n'.join(data)
        self._cache[label] = {'data': data, 'time': time.time()}

    # Retreive data from the cache
    def cacheGet(self, label, timeoutHrs):
        if label not in self._cache.keys():
            return None

        entry = self._cache[label]
        if entry['time'] > time.time() - timeoutHrs * 3600 or timeoutHrs == 0:
            return self._cache[label]['data']
        return None

    def myPath(self):
        # This will get us the program's directory, even if we are frozen using py2exe.
        # Determine whether we've been compiled by py2exe
        if hasattr(sys, "frozen"):
            return os.path.dirname(unicode(sys.executable, sys.getfilesystemencoding()))
        return os.path.dirname(unicode(__file__, sys.getfilesystemencoding()))

    # Return dictionary words and/or names
    def dictwords(self):
        return []

    # Return dictionary names
    def dictnames(self):
        return []

    # Fetch a URL, return the response object
    def fetchUrl(self, url, fatal=False, cookies=None, timeout=30,
                 useragent='Spiderfoot', headers=None, noLog=False,
                 postData=None, dontMangle=False, sizeLimit=None,
                 headOnly=False, isJson=False):
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

                hdr = requests.head(url, headers=header, proxies=proxies, verify=False)
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

                    hdr = requests.head(result['realurl'], proxies=proxies, headers=header, verify=False, timeout=timeout)
                    size = int(hdr.headers.get('content-length', 0))
                    result['realurl'] = hdr.headers.get('location', result['realurl'])
                    result['code'] = str(hdr.status_code)

                    if size > sizeLimit:
                        return result

            req = urllib.request.Request(url, postData, header)
            if proxies != None:
                req.set_proxy(https_proxy, 'https')
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

            if isJson:
                _ = requests.get(url, headers=header, proxies=proxies)

                for k, v in _.headers.items():
                    result['headers'][k.lower()] = v

                result['realurl'] = url

                try:
                    result['content'] = _.json()
                except Exception as e:
                    result['content'] = None
                    self.debug('Unable to load JSON from {} - {}'.format(url, e))
                result['code'] = str(_.status_code)
                result['status'] = 'OK'
            else:
                if proxies != None:
                    opener = urllib.request.build_opener(urllib.request.ProxyHandler(proxies))
                else:
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

    # Find all URLs within the supplied content. This does not fetch any URLs!
    # A dictionary will be returned, where each link will have the keys
    # 'source': The URL where the link was obtained from
    # 'original': What the link looked like in the content it was obtained from
    # The key will be the *absolute* URL of the link obtained, so for example if
    # the link '/abc' was obtained from 'http://xyz.com', the key in the dict will
    # be 'http://xyz.com/abc' with the 'original' attribute set to '/abc'
    def parseLinks(self, url, data, domains, parseText=True):
        returnLinks = dict()
        urlsRel = []

        if type(domains) is str:
            domains = [domains]

        tags = {
            'a': 'href',
            'img': 'src',
            'script': 'src',
            'link': 'href',
            'area': 'href',
            'base': 'href',
            'form': 'action'
        }

        try:
            proto = url.split(":")[0]
        except BaseException as e:
            proto = "http"
        if proto == None:
            proto = "http"

        if data is None or len(data) == 0:
            self.debug("parseLinks() called with no data to parse.")
            return None

        try:
            for t in tags.keys():
                for lnk in BeautifulSoup(data, "lxml", parse_only=SoupStrainer(t)).find_all(t):
                    if lnk.has_attr(tags[t]):
                        urlsRel.append([None, lnk[tags[t]]])
        except BaseException as e:
            self.error("Error parsing with BeautifulSoup: " + str(e), False)
            return None

        # Find potential links that aren't links (text possibly in comments, etc.)
        data = urllib.parse.unquote(data)
        for domain in domains:
            if parseText:
                try:
                    # Because we're working with a big blob of text now, don't worry
                    # about clobbering proper links by url decoding them.
                    regRel = re.compile('(.)([a-zA-Z0-9\-\.]+\.' + domain + ')',
                                        re.IGNORECASE)
                    urlsRel = urlsRel + regRel.findall(data)
                except Exception as e:
                    self.error("Error applying regex2 to: " + data + "(" + str(e) + ")", False)
                try:
                    # Some links are sitting inside a tag, e.g. Google's use of <cite>
                    regRel = re.compile('([>\"])([a-zA-Z0-9\-\.\:\/]+\.' + domain + '/.[^<\"]+)', re.IGNORECASE)
                    urlsRel = urlsRel + regRel.findall(data)
                except Exception as e:
                    self.error("Error applying regex3 to: " + data + "(" + str(e) + ")", False)

            # Loop through all the URLs/links found
            for linkTuple in urlsRel:
                # Remember the regex will return two vars (two groups captured)
                junk = linkTuple[0]
                link = linkTuple[1]
                if type(link) != unicode:
                    link = unicode(link, 'utf-8', errors='replace')
                linkl = link.lower()
                absLink = None

                if len(link) < 1:
                    continue

                # Don't include stuff likely part of some dynamically built incomplete
                # URL found in Javascript code (character is part of some logic)
                if link[len(link) - 1] == '.' or link[0] == '+' or \
                                'javascript:' in linkl or '()' in link:
                    self.debug('unlikely link: ' + link)
                    continue
                # Filter in-page links
                if re.match('.*#.[^/]+', link):
                    self.debug('in-page link: ' + link)
                    continue

                # Ignore mail links
                if 'mailto:' in linkl:
                    self.debug("Ignoring mail link: " + link)
                    continue

                # URL decode links
                if '%2f' in linkl:
                    link = urllib.parse.unquote(link)

                # Capture the absolute link:
                # If the link contains ://, it is already an absolute link
                if '://' in link:
                    absLink = link

                # If the link starts with a /, the absolute link is off the base URL
                if link.startswith('/'):
                    absLink = self.urlBaseUrl(url) + link

                # Protocol relative URLs
                if link.startswith('//'):
                    absLink = proto + ':' + link

                # Maybe the domain was just mentioned and not a link, so we make it one
                if absLink is None and domain.lower() in link.lower():
                    absLink = proto + '://' + link

                # Otherwise, it's a flat link within the current directory
                if absLink is None:
                    absLink = self.urlBaseDir(url) + link

                # Translate any relative pathing (../)
                absLink = self.urlRelativeToAbsolute(absLink)
                returnLinks[absLink] = {'source': url, 'original': link}

        return returnLinks

    # Extract the top level directory from a URL
    def urlBaseDir(self, url):

        bits = url.split('/')

        # For cases like 'www.somesite.com'
        if len(bits) == 0:
            return url + '/'

        # For cases like 'http://www.blah.com'
        if '://' in url and url.count('/') < 3:
            return url + '/'

        base = '/'.join(bits[:-1])
        return base + '/'

    # Turn a relative path into an absolute path
    def urlRelativeToAbsolute(self, url):
        finalBits = list()

        if '..' not in url:
            return url

        bits = url.split('/')

        for chunk in bits:
            if chunk == '..':
                # Don't pop the last item off if we're at the top
                if len(finalBits) <= 1:
                    continue

                # Don't pop the last item off if the first bits are not the path
                if '://' in url and len(finalBits) <= 3:
                    continue

                finalBits.pop()
                continue

            finalBits.append(chunk)
        return '/'.join(finalBits)

    # Extract the scheme and domain from a URL
    # Does not return the trailing slash! So you can do .endswith()
    # checks.
    def urlBaseUrl(self, url):
        if '://' in url:
            bits = re.match('(\w+://.[^/:\?]*)[:/\?].*', url)
        else:
            bits = re.match('(.[^/:\?]*)[:/\?]', url)

        if bits is None:
            return url.lower()
        return bits.group(1).lower()


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

    # Used to clear any listener relationships, etc. This is needed because
    # Python seems to cache local variables even between threads.
    def clearListeners(self):
        self._listenerModules = list()
        self._stopScanning = False

    # Will always be overridden by the implementer.
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
