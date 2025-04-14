from utils import cv2PutText, time_consumed

import cv2 as cv
import numpy as np
import base64

import logging

# Don't let paddleocr screw up our logging levels
original_level = logging.getLogger().getEffectiveLevel()
from paddleocr import PaddleOCR
logging.getLogger().setLevel(original_level)

class PaddleOCRClient:

    @staticmethod
    @time_consumed
    def ocr(base64_screenshot, debug_output=False):
        logging.getLogger("ppocr").setLevel(logging.ERROR if not debug_output else logging.DEBUG)
        ocr = PaddleOCR(lang='ch', det_limit_side_len=2000, db_unclip_ratio=2.0, det_db_thresh=0.3, det_db_box_thresh=0.3, det_db_score_mode='slow', use_dilation=True, drop_score=0.5) # need to run only once to download and load model into memory
        img = cv.imdecode(np.frombuffer(base64.b64decode(base64_screenshot), np.uint8), cv.IMREAD_COLOR)
        #img = cv.bitwise_not(img)  # Is this necessary?

        rgb = cv.cvtColor(img, cv.COLOR_BGR2RGBA)
        result = ocr.ocr(rgb)

        elements = []
        
        for res in result:
            if not res:
                continue
            for line in res:
                top_left = list(map(int, line[0][0]))
                bottom_right = list(map(int, line[0][2]))
                text, conf = line[1]
                width, height = bottom_right[0] - top_left[0], bottom_right[1] - top_left[1]
                elements.append((top_left[0], top_left[1], width, height, text, conf))
                if debug_output:
                    cv.rectangle(img, top_left, bottom_right, (0, 255, 0), 2)
                    top_left[1] -= 40
                    cv2PutText(img, text, top_left, cv.FONT_HERSHEY_SIMPLEX, 1.8, (255, 0, 0), 1)
        
        if debug_output:
            cv.imwrite("screenshot-ocr.png", img)

        return elements

