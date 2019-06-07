# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_bitcoin_cash
# Purpose:      SpiderFoot plug-in to look up Bitcoin Cash address balance and transactions
#
# Author:    Ajoy Oommen <ajoyoommen@gmail.com>
#
# Created:     07/06/2019
# Licence:     MIT
# ------------------------------------------------------

from sflib import SpiderFootPlugin, SpiderFootEvent


class sfp_bitcoin_cash(SpiderFootPlugin):
    opts = {
        "api_root": "https://bch-chain.api.btc.com/v3",
        "transactions_limit": 50
    }
    results = dict()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ['BITCOIN_CASH_ADDRESS']

    def producedEvents(self):
        return ["BITCOIN_CASH_ADDRESS_DATA"]

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
            "balance": self.query_api("/address/{}".format(eventData)),
            "transactions": self.query_api("/address/{}/tx?pagesize={}".format(eventData, self.opts["transactions_limit"]))
        }

        evt = SpiderFootEvent("BITCOIN_CASH_ADDRESS_DATA", data, self.__name__, event)
        self.notifyListeners(evt)
        return None