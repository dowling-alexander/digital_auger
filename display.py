import threading
import time
import os
import signal
import logging


from PIL import Image, ImageDraw
from logger import Logger

logger = Logger(name="display.py", level=logging.DEBUG)

class Display:
    def __init__(self):
        logger.info("Initialising Display received")

    def run(self):
        logger.info("made it to display run")
        image = Image.new('1', (122,255))
        draw = ImageDraw.Draw(image)
        draw.rectangle((1,1, 120,250), fill=255)

        image.show()


