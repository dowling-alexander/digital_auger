import json
import time
import logging
import sys
import threading

from logger import Logger
from init_shared import shared_data

logger = Logger(name="orchestrator.py", level=logging.DEBUG)

class Orchestrator:
    def __init__(self):
        self.shared_data = shared_data
