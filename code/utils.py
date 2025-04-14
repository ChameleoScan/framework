import json
import io, os
from typing import Callable
import time, random

import numpy as np
import cv2
from PIL import Image, ImageDraw, ImageFont

# Configure logging
import logging
logger = logging.getLogger(__name__)

logging.getLogger('PIL').setLevel(logging.ERROR)

def sleep(seconds: float|None = None):
    seconds = seconds if seconds is not None else random.uniform(0.5, 1.5)
    time.sleep(seconds)

def wait_until(func: Callable[[], object], condition: Callable[[object], bool], timeout: float = 10.0, interval: float|None = None) -> object:
    start_time = time.time()
    while time.time() - start_time < timeout:
        if condition(ret := func()):
            return ret
        sleep(interval)
    try:
        raise TimeoutError(f"Timeout exceeded: {timeout} seconds")
    except Exception as e:
        logger.error('While waiting for condition:')
        raise e

def randint(a: int, b: int) -> int:
    return random.randint(a, b)

def rand(a: float = 0.0, b: float = 1.0) -> float:
    return random.uniform(a, b)

def cv2PutText(img: cv2.typing.MatLike,
    text: str,
    org: cv2.typing.Point,
    fontFace: int,
    fontScale: float,
    color: cv2.typing.Scalar,
    thickness: int = ...,
    lineType: int = ...,
    bottomLeftOrigin: bool = ...
) -> cv2.typing.MatLike:
    oimg = img
    if (isinstance(img, np.ndarray)):
        img = Image.fromarray(cv2.cvtColor(img, cv2.COLOR_BGR2RGB))
    draw = ImageDraw.Draw(img)
    fontStyle = ImageFont.truetype("./simsun.ttc", 20 * fontScale, encoding="utf-8")
    draw.text(org, text, color, font=fontStyle, stroke_width=thickness, stroke_fill=color)
    img1 = cv2.cvtColor(np.asarray(img), cv2.COLOR_RGB2BGR)
    np.copyto(oimg, np.asarray(img1))
    return img

def base64_img(path: str) -> str:
    import base64
    with open(path, 'rb') as f:
        return base64.b64encode(f.read()).decode('utf-8')

def base64_imglike(img: cv2.typing.MatLike) -> str:
    import base64
    _, buffer = cv2.imencode('.png', img)
    return base64.b64encode(buffer).decode('utf-8')

def suppress_status_bar(image: str|io.BytesIO, status_bar_pixels: int) -> str|io.BytesIO:
    """Suppresses the status bar at the top of the image (base64 or BytesIO)"""
    if isinstance(image, str):
        import base64
        image_data = base64.b64decode(image)
    else:
        image_data = image
    
    nparr = np.frombuffer(image_data, np.uint8)
    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    
    img[0:status_bar_pixels, :] = [0, 0, 0]
    
    _, buffer = cv2.imencode('.png', img)
    
    if isinstance(image, str):
        return base64.b64encode(buffer).decode('utf-8')
    else:
        return buffer.tobytes()

def mkdir(path: str):
    if not os.path.exists(path):
        os.makedirs(path, exist_ok=True)

def run_process(cmd: list[str]) -> str:
    import subprocess
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout

def crop_image(image: str|io.BytesIO, x: int, y: int, width: int, height: int) -> io.BytesIO:
    if isinstance(image, str):
        import base64
        image_data = io.BytesIO(base64.b64decode(image))
    else:
        image_data = image
    img = Image.open(image_data)
    img = img.crop((x, y, x + width, y + height))
    # Convert PIL Image to bytes
    img_byte_arr = io.BytesIO()
    img.save(img_byte_arr, format='PNG')
    img_byte_arr.seek(0)
    return img_byte_arr

def _dump_xml(uielements: dict) -> str:
    xmlstring = ''
    def dump(data: dict, indent: int = 0):
        nonlocal xmlstring
        xmlstring += '  ' * indent
        xmlstring += '<' + '|'.join(data['type']) if isinstance(data['type'], list) else data['type'] + ' id=' + str(data['id']) + ''
        for key, value in data.items():
            if key == 'type' or key == 'subviews' or key == 'id':
                continue
            if isinstance(value, dict):
                for k, v in value.items():
                    xmlstring += ' ' + key + '.' + k + '=' + json.dumps(v, ensure_ascii=False, indent=0) + ''
            elif isinstance(value, list):
                xmlstring += ' ' + key + '=' + '|'.join(json.dumps(v, ensure_ascii=False, indent=0) for v in value) + ''
            else:
                xmlstring += ' ' + key + '=' + json.dumps(value, ensure_ascii=False, indent=0) + ''
        xmlstring += '>\n'
        for subview in data.get('subviews', []):
            dump(subview, indent + 1)
        xmlstring += '  ' * indent + '</' + '|'.join(data['type']) if isinstance(data['type'], list) else data['type'] + '>\n'
    dump(uielements)
    return xmlstring

_time_consumed = []
def time_consumed(func):
    import functools, time
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        global _time_consumed
        _time_consumed.append((func.__qualname__, end_time - start_time))
        _time_consumed = _time_consumed[-100:]
        logger.debug(f"Function {func.__qualname__} consumed {end_time - start_time} seconds")
        return result
    return wrapper

def clear_time_consumed():
    global _time_consumed
    _time_consumed.clear()

def get_time_consumed(func_name: str) -> list[float]:
    return [t for n, t in _time_consumed if n == func_name]

_token_record = []
def token_record(func_name: str, input_token: int, output_token: int):
    global _token_record
    _token_record.append((func_name, (input_token, output_token)))
    _token_record = _token_record[-100:]

def clear_token_record():
    global _token_record
    _token_record.clear()

def get_token_consumed(func_name: str) -> list[tuple[int, int]]:
    return [t for n, t in _token_record if n == func_name]

__all__ = ['sleep', 'wait_until', 'cv2PutText', 'rand', 'randint', 'base64_img', 'base64_imglike', 'suppress_status_bar', 'mkdir', 'run_process', 'crop_image', 'time_consumed', 'clear_time_consumed', 'get_time_consumed', 'token_record', 'clear_token_record', 'get_token_consumed']