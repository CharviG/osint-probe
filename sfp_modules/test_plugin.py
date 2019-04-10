# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         test_plugin
# Purpose:      For testing plugin features
#
# Author:      Ajoy Oommen <ajoyoommen@gmail.com>
#
# Created:     10/04/2019
# Copyright:   (c) Ajoy Oommen, 2019
# Licence:     GPL
# -------------------------------------------------------------------------------

from sflib import SpiderFootPlugin, SpiderFootEvent


class test_plugin(SpiderFootPlugin):
    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc

    def watchedEvents(self):
        return ['TEST_EVENT']

    def producedEvents(self):
        return ['TEST_EVENT']

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        evt = SpiderFootEvent('TEST_EVENT', 'message', self.__name__, event)
        self.notifyListeners(evt)