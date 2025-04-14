import concurrent.futures
import datetime
import sqlite3
import time
from tqdm import tqdm
import base64
from urllib.parse import urlparse
import requests

import logging
logger = logging.getLogger(__name__)

session = None
def get_app_baseinfo(appid: str | int) -> dict:
    raise NotImplementedError('Due to compliance restrictions, this part of code has been omitted.')

def get_app_comment(appid: str | int) -> list:
    raise NotImplementedError('Due to compliance restrictions, this part of code has been omitted.')

def get_app_recommend(appid: str | int) -> list:
    raise NotImplementedError('Due to compliance restrictions, this part of code has been omitted.')

if __name__ == '__main__':
    pass
