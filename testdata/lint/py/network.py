# network.py is a capability lint fixture (task 4.2): every line here is a
# genuine match for the network detection class table (spec 9). Comment
# based and dynamic import based limitations are exercised separately in
# falsenegatives.py, not mixed in here, so this file's detection count stays
# exactly one per table entry.

import requests
from requests import get
import httpx
from httpx import Client
import urllib
from urllib import request
import socket
from socket import socket as raw_socket
import aiohttp
from aiohttp import ClientSession
