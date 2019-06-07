# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_ripple
# Purpose:      SpiderFoot plug-in to look up Ripple address balance and transactions
#
# Author:    Ajoy Oommen <ajoyoommen@gmail.com>
#
# Created:     07/06/2019
# Licence:     MIT
# ------------------------------------------------------

from sflib import SpiderFootPlugin, SpiderFootEvent


class sfp_ripple(SpiderFootPlugin):
    opts = {
        "api_root": "https://data.ripple.com/v2",
        "transactions_limit": 50
    }
    results = dict()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ['RIPPLE_ADDRESS']

    def producedEvents(self):
        return ["RIPPLE_ADDRESS_DATA"]

    def query_api(self, url):
        res = self.sf.fetchUrl(
            self.opts["api_root"] + url,
            timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'],
            isJson=True)
        if res['content'] is None:
            self.sf.info("Empty content for " + url)
            return None
        try:
            data = res['content']
        except Exception as e:
            self.sf.debug("Error processing JSON response.")
            return None
        return data

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None
        else:
            self.results[eventData] = True

        data = {
            "balance": self.query_api("/accounts/{}/balances".format(eventData)),
            "transactions": self.query_api("/accounts/{}/transactions?limit={}".format(eventData, self.opts["transactions_limit"]))
        }

        evt = SpiderFootEvent("RIPPLE_ADDRESS_DATA", data, self.__name__, event)
        self.notifyListeners(evt)
        return None