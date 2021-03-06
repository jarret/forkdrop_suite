# Copyright (c) 2018 PrimeVR
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php

import requests
import hashlib
import json
import sys
import os
import tempfile

from lib.utl.print import print_red, red_str, chill_yellow_str, chill_green_str
from lib.utl.dir_manager import DirectoryManager
from lib.utl.file_manager import FileManager

###############################################################################
# pull info from the web
###############################################################################

FORKDROP_URL = "https://forkdrop.io/json/suite.json"

TOR_ADDR_URL = "https://blockchainbdgpzk.onion/address/%s?format=json"
TOR_TX_URL = "https://blockchainbdgpzk.onion/tx/%s?format=json"

WEB_ADDR_URL = "https://blockchain.info/address/%s?format=json"
WEB_TX_URL = "https://blockchain.info/tx/%s?format=json"

HEADERS = {
    "User-Agent":      "forkdrop-script",
    "From":            "forkdrop@protonmail.com",
    "Accept-Encoding": "gzip",
}

CAPTCHA_MSG ="""
%s we attempted a request of the url:

%s

however, we got rejected with a challenge page designed to reject automated
scraping (such as this). A potential workaround is to visit this URL via Tor
Browser and obtain the JSON.  If the --cache-requests option is used on this
script and the parsable JSON content of this url is written to the file:

%s

This script will treat the content in the file as the content at that URL.

"""

BI_CAPTCHA_MSG ="""
%s we attempted a request of the url:

%s

Blockchain.info sometimes rejects requests over Tor with a captcha as a defense
against atomated scraping from anonymous sources. This might go away after
waiting for a period of time. One option might be to try disconnecting and
re-connecting to Tor in order to obtain a different exit point which might not
be banned.

A potential workaround is to visit this URL via Tor Browser and obtain the
JSON.  If the --cache-requests option is used on this script and the parsable
JSON content of this url is written to the file:

%s

This script will treat the content in the file as the content at that URL.

"""

class WebData(object):
    def __init__(self, tails=True, cache=False):
        if tails:
            self.tx_url = TOR_TX_URL
            self.addr_url = TOR_ADDR_URL
        else:
            self.tx_url = WEB_TX_URL
            self.addr_url = WEB_ADDR_URL
        self.tails = tails
        self.cache = cache

    def _check_captcha(self, r, url):
        if r.status_code != 403:
            print("got status code %d from query to %s" % (r.status_code, url))
            return
        if "captcha" not in r.text:
            print("Got 403 status from %s, but it doesn't seem to be a "
                    "captcha issue (which sometimes occurs). "
                    "this is unexpected what to do. If you can, please file "
                    "an issue on the project github. Text of "
                    "response: %s" % (url, r.text))
            return
        dm = DirectoryManager()
        cache_file = dm.get_query_cache_path(url)
        if "blockchainbdgpzk" in url:
            msg = BI_CAPTCHA_MSG % (red_str("ERROR:"), url,
                                    chill_green_str(cache_file))
        else:
            msg = CAPTCHA_MSG % (red_str("ERROR:"), url,
                                 chill_green_str(cache_file))
        print(msg)
        sys.exit("*** could not fetch data at url - rejected")

    def _request(self, url):
        proxies = {"https": "socks5://127.0.0.1:9050"} if self.tails else None
        r = requests.get(url, headers=HEADERS, proxies=proxies)
        if r.status_code != 200:
            self._check_captcha(r, url)
            print_red("Web request err %d" % r.status_code)
            sys.exit("*** could not fetch required web data from %s" % url)

        return r.text

    def _text_dl(self, url):
        if ".onion" in url:
            print("tor fetch: %s" % chill_green_str(url))
        else:
            print("web fetch: %s" % chill_yellow_str(url))

        dm = DirectoryManager()
        if self.cache and dm.is_query_cached(url):
            cache_file = dm.get_query_cache_path(url)
            return FileManager.read_text(cache_file)

        t = self._request(url)

        if self.cache:
            cache_file = dm.get_query_cache_path(url)
            FileManager.write_text(cache_file, t)

        return t

    def _json_dl(self, url):
        text = self._text_dl(url)
        try:
            j = json.loads(text)
        except ValueError:
            print("We expected to get a json-formatted response from the "
                  "url: %s however, we were able to decode it. The text "
                  "of the response is:\n\n%s" % (red_str(url), text))
            sys.exit("*** could not decode response")
        return j

    def fetch_forkdrop_info(self):
        return self._json_dl(FORKDROP_URL)

    def fetch_tx_info(self, txid):
        return self._json_dl(self.tx_url % txid)

    def fetch_addr_info(self, addr):
        return self._json_dl(self.addr_url % addr)

    def fetch_web_url_json_info(self, url):
        return self._json_dl(url)

    def fetch_web_url_text_info(self, url):
        return self._text_dl(url)
