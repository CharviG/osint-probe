# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:      sfp_cryptocurrency
# Purpose:   SpiderFoot plug-in to look up Cryptocurrency address balances and transactions
#
# Author:    Ajoy Oommen <ajoyoommen@gmail.com>
#
# Created:   11/06/2019
# Licence:   MIT
# ------------------------------------------------------
import re

from sflib import SpiderFootPlugin, SpiderFootEvent


CURRENCIES = {
    "bitcoin": {
        # 17Wk4GPKw9nZ9PbspzaxN3fv1L2m9NA9dg
        "symbol": "BTC",
        "regex": "^[13][a-km-zA-HJ-NP-Z0-9]{26,33}$",
        "transactions": "https://blockchain.info/rawaddr/{address}?limit={limit}"
    },
    "bitcoin_cash": {
        # 13usM2ns3f466LP65EY1h8hnTBLFiJV6rD
        "symbol": "BCH",
        "regex": "^([13][a-km-zA-HJ-NP-Z1-9]{25,34})|^((bitcoincash:)?(q|p)[a-z0-9]{41})|^((BITCOINCASH:)?(Q|P)[A-Z0-9]{41})$",
        "transactions": "https://bch-chain.api.btc.com/v3/address/{address}/tx?pagesize={limit}",
        "balance": "https://bch-chain.api.btc.com/v3/address/{address}"
    },
    "dash": {
        # XbUCHXtCber1hcZuZ2RcJSZ9ZscNTTtNDf
        "symbol": "DASH",
        "regex": "^X[1-9A-HJ-NP-Za-km-z]{33}$",
        "balance": "https://api.blockcypher.com/v1/dash/main/addrs/{address}/balance",
        "transactions": "https://api.blockcypher.com/v1/dash/main/addrs/{address}?limit={limit}"
    },
    "dogecoin": {
        # DTnt7VZqR5ofHhAxZuDy4m3PhSjKFXpw3e
        "symbol": "DOGE",
        "regex": "^D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}$",
        "balance": "https://api.blockcypher.com/v1/doge/main/addrs/{address}/balance",
        "transactions": "https://api.blockcypher.com/v1/doge/main/addrs/{address}?limit={limit}"
    },
    "ethereum": {
        # 0xf6e76de8e0caaa8f9a9f82db5f00966d727515ed
        "symbol": "ETH",
        "regex": "^0x[a-fA-F0-9]{40}$",
        "balance": "https://blockscout.com/eth/mainnet/api?module=account&action=balance&address={address}",
        "transactions": "https://blockscout.com/eth/mainnet/api?module=account&action=txlist&address={address}&offset={limit}",
        "tokens": "https://blockscout.com/eth/mainnet/api?module=account&action=tokenlist&address={address}"
    },
    "litecoin": {
        # LSDL5DvKDDhEbiSeUSHN6gWCAgdk8nXHaQ
        "symbol": "LTC",
        "regex": "^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}$",
        "balance": "https://api.blockcypher.com/v1/ltc/main/addrs/{address}/balance",
        "transactions": "https://api.blockcypher.com/v1/ltc/main/addrs/{address}?limit={limit}"
    },
    "monero": {
        "symbol": "XMR",
        "regex": "^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$"
    },
    "neo": {
        # AaQzU121MKMrNjyqwzTq8ruBu9o1obQsfJ
        "symbol": "NEO",
        "regex": "^A[0-9a-zA-Z]{33}$",
        "balance": "https://api.neoscan.io/api/main_net/v1/get_balance/{address}",
        "transactions": "https://api.neoscan.io/api/main_net/v1/get_address_abstracts/{address}/1"
    },
    "ripple": {
        # rf1BiGeXwwQoi8Z2ueFYTEXSwuJYfV2Jpn
        "symbol": "XRP",
        "regex": "^r[0-9a-zA-Z]{24,34}$",
        "balance": "https://data.ripple.com/v2/accounts/{address}/balances",
        "transactions": "https://data.ripple.com/v2/accounts/{address}/transactions?limit={limit}"
    },
    "zcash": {
        # t3Vz22vK5z2LcKEdg16Yv4FFneEL1zg9ojd
        "symbol": "ZEC",
        "regex": "^[tz][a-km-zA-HJ-NP-Z0-9]{26,34}$",
        "balance": "https://api.zcha.in/v2/mainnet/accounts/{address}"
    }
}


class sfp_cryptocurrency(SpiderFootPlugin):
    opts = {
        "transactions_limit": 50
    }
    results = dict()

    def currency_type(self, address):
        matches = []

        for name, obj in CURRENCIES.items():
            p = re.compile(obj["regex"])
            match = p.match(address)
            if match:
                matches.append(name)
        return matches if matches else False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ['CRYPTOCURRENCY_ADDRESS']

    def producedEvents(self):
        return ["CRYPTOCURRENCY_ADDRESS_DATA"]

    def query_api(self, url):
        res = self.sf.fetchUrl(
            url,
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

        # Check address regexes for identifying currency
        matched_currencies = self.currency_type(eventData)

        meta = {
            "address": eventData,
            "limit": self.opts["transactions_limit"]
        }

        for currency_type in matched_currencies:
            currency_data = CURRENCIES[currency_type]
            data = {
                "currency": currency_type,
                "symbol": currency_data["symbol"]
            }

            params = ["balance", "transactions", "tokens"]
            for param in params:
                if param in currency_data.keys():
                    data[param] = self.query_api(currency_data[param].format(**meta))

            evt = SpiderFootEvent("CRYPTOCURRENCY_ADDRESS_DATA", data, self.__name__, event)
            self.notifyListeners(evt)
        return None
