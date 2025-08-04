import os
import json
import logging
from logger import Logger
from PIL import Image, ImageFont
from epd_helper import EPDHelper

logger = Logger(name="shared.py", level=logging.DEBUG)

class SharedData:

    def __init__(self):
        #self.load_fonts()
        self.default_config = self.get_default_config()






    def load_fonts(self):
        """Load the fonts."""
        try:
            logger.info("Loading fonts...")
            self.font_arial14 = self.load_font('Arial.ttf', 14)
            self.font_arial11 = self.load_font('Arial.ttf', 11)
            self.font_arial9 = self.load_font('Arial.ttf', 9)
            self.font_arialbold = self.load_font('Arial.ttf', 12)
            self.font_viking = self.load_font('Viking.TTF', 13)

        except Exception as e:
            logger.error(f"Error loading fonts: {e}")
            raise

    def load_font(self, font_name, size):
        """Load a font."""
        try:
            return ImageFont.truetype(os.path.join(self.fontdir, font_name), size)
        except Exception as e:
            logger.error(f"Error loading font {font_name}: {e}")
            raise

    def get_default_config(self):
        """this is just going to generate the default configs"""
        logger.info("I remember")
        return {

            "startup_delay": 10,
            "screen_delay": 1,
            "ref_width":  122,
            "ref_height": 255,
            "epd_type": "epd2in13_V4"
        }



