from abc import ABC, abstractmethod
import json
from typing import Callable, List

from gpt_cls import GPTClient, UIElementType, UIView, UIElement

from utils import time_consumed

class BaseUI(ABC):
    @abstractmethod
    def __init__(self, vars):
        pass

    @classmethod
    @abstractmethod
    def create_ui(cls, vars):
        pass

    def replace_ui(self, vars):
        self.__init__(vars)
        return self

    @abstractmethod
    def getui(self):
        pass

    @staticmethod
    @abstractmethod
    def post_process_ui(uielements: dict, base64_screenshot: str) -> tuple[dict, dict]:
        pass

    @staticmethod
    def analyze_ui(uielements: dict, base64_screenshot: str) -> UIView:
        # Use GPT-4o to analyze the UI elements and provide a response
        gpt = GPTClient()

        focus_ads = False

        if BaseUI.element_selector(uielements, 'name', '广告', strict=True) is not None \
            or BaseUI.element_selector(uielements, 'name', '打开或下载第三方应用', strict=True) is not None\
                or BaseUI.element_selector(uielements, 'ocr_text', '广告', strict=True) is not None:
            focus_ads = True
        
        analyzed = gpt.analyze_screenshot(base64_screenshot, uielements, focus_ads)

        if analyzed.ads and analyzed.ads.is_ad_closeable and analyzed.ads.ad_close_button_id > 0:
            # Add the close button if not present (which is strange but frequently happens)
            if not any(element.id == analyzed.ads.ad_close_button_id for element in analyzed.elements):
                analyzed.action_elements.append(UIElement(id=analyzed.ads.ad_close_button_id, ui_type='IconButton', description='Close button for the'+(' urgent topmost' if analyzed.ads.is_ad_topmost else '')+' advertisement', text='Close', clickability=1.0, location=''))

        # Make sure buttons and text inputs are aligned
        vid_map = BaseUI.get_vid_map(uielements)
        for element in analyzed.elements:
            if element.id in vid_map:
                if any(k in vid_map[element.id].get('type', '') for k in ['TextField', 'TextView']) and element.ui_type != UIElementType.INPUT_TEXT:
                    element.ui_type = UIElementType.INPUT_TEXT
                elif 'Button' in vid_map[element.id].get('type', '') and element.ui_type not in [UIElementType.BUTTON, UIElementType.TEXT_BUTTON, UIElementType.ICON_BUTTON]:
                    element.ui_type = UIElementType.OTHER_INTERACTABLE

        return analyzed
    
    @staticmethod
    def get_frame(element: dict) -> dict:
        if 'absolute_frame' in element:
            return element['absolute_frame']
        elif 'frame_box' in element:
            return {'x': element['frame_box']['top_left']['x'], 'y': element['frame_box']['top_left']['y'], 'width': element['frame_box']['right_bottom']['x'] - element['frame_box']['top_left']['x'], 'height': element['frame_box']['right_bottom']['y'] - element['frame_box']['top_left']['y']}
        else:
            return element['_absolute_frame']
        
    @staticmethod
    def get_center(element: dict) -> dict:
        frame = BaseUI.get_frame(element)
        return {'x': frame['x'] + frame['width'] // 2, 'y': frame['y'] + frame['height'] // 2}
    
    @staticmethod
    def find_suitable_element(uielements: dict, x: int, y: int, width: int, height: int, tolerance: float = 0.01) -> tuple[dict, int, int]:
        """Find the most suitable (smallest containing) element at the given rectangle"""

        if not uielements:
            return None, 0, 0
            
        suitable_element = None
        max_depth = -1
        min_area = float('inf')
        
        def check_element(element, depth=0):
            nonlocal suitable_element, max_depth, min_area
            
            frame = BaseUI.get_frame(element)
            # Check if rectangle overlaps with element bounds
            if (frame['x'] - frame['width'] * tolerance <= x and x + width <= frame['x'] + frame['width'] + frame['width'] * tolerance and
                frame['y'] - frame['height'] * tolerance <= y and y + height <= frame['y'] + frame['height'] + frame['height'] * tolerance):
                    
                area = frame['width'] * frame['height']
                # Update if this contains smaller area
                if area < min_area or (area == min_area and depth > max_depth):
                    suitable_element = element
                    min_area = area
                    max_depth = depth
                    
            # Recursively check subviews
            for subview in element.get('subviews', []):
                check_element(subview, depth + 1)
                
        # Start recursive search from root element
        root_element = uielements
        check_element(root_element)
        
        return suitable_element, max_depth, min_area

    @staticmethod
    def get_vid_map(uielements: dict) -> dict:
        vid_map = {}
        def traverse(view):
            vid_map[view['id']] = view
            for subview in view.get('subviews', []):
                traverse(subview)
        traverse(uielements)
        return vid_map
    
    @staticmethod
    def is_ui_equal(uielements1: dict, uielements2: dict) -> bool:
        import copy
        uielements1 = copy.deepcopy(uielements1)
        uielements2 = copy.deepcopy(uielements2)

        def check_view(view1, view2):
            if any(k not in view1 or k not in view2 or view1[k] != view2[k] for k in ['id', 'type']):
                return False
            if len(view1['subviews']) != len(view2['subviews']):
                return False
            view1['subviews'].sort(key=lambda x: x['id'])
            view2['subviews'].sort(key=lambda x: x['id'])
            for subview1, subview2 in zip(view1['subviews'], view2['subviews']):
                if not check_view(subview1, subview2):
                    return False
            return True
        
        text_list1 = BaseUI.get_text_list(uielements1)
        text_list2 = BaseUI.get_text_list(uielements2)
        jaccard_similarity = len(set(text_list1) & set(text_list2)) / len(set(text_list1) | set(text_list2))
        diff_len = len(set(text_list1) - set(text_list2))

        return check_view(uielements1, uielements2) or (diff_len <= 4 and jaccard_similarity >= 0.8)

    @staticmethod
    def get_text_list(uielements: dict) -> List[str]:
        text_list = set()
        def traverse(view):
            for key in ['text', 'name', 'value', 'label']:
                if key in view:
                    val = view[key] if isinstance(view[key], str) else '/'.join(view[key])
                    text_list.add(view.get('type', '') + ': ' + key + '="' + val + '"')
            for subview in view.get('subviews', []):
                traverse(subview)
        traverse(uielements)
        return list(text_list)
    
    @staticmethod
    def element_selector(uielements: dict, name: str, value: str, strict: bool = False) -> dict|None:
        if (strict and uielements.get(name, '') == value) or (not strict and value.lower() in uielements.get(name, '').strip().lower()):
            return uielements
        for subview in uielements.get('subviews', []):
            if (sub := BaseUI.element_selector(subview, name, value, strict)) is not None:
                return sub
        return None
    
    @staticmethod
    def element_selector_custom(uielements: dict, func: Callable[[dict], bool]) -> dict|None:
        if func(uielements):
            return uielements
        for subview in uielements.get('subviews', []):
            if (sub := BaseUI.element_selector_custom(subview, func)) is not None:
                return sub
        return None
    


class AppiumUI(BaseUI):
    def __init__(self, vars):
        (self.gbscript, self.appium) = vars

    @classmethod
    def create_ui(cls, vars):
        """Create the UI object"""
        return cls(vars)
    
    @staticmethod
    def getui_raw(uist):
        """Get the UI elements by existing content"""
        uielements = uist['elements']
        screen_scale = uist['screenscale']

        VID = 0
        def getvid():
            nonlocal VID
            VID += 1
            return VID
        VID_MAP = {}
        
        def process_view(view):
            view['subviews'] = view.get('subviews', [])
            for key in list(view.keys()):
                if key in ['subviews']:
                    continue
                if key.startswith('@'):
                    view[key[1:]] = view.pop(key)
                else:
                    childs = []
                    def flap_list(l):
                        if isinstance(l, list):
                            for i in l:
                                flap_list(i)
                        else:
                            childs.append(l)
                    flap_list(view.pop(key))
                    view['subviews'].extend(childs)

            view['id'] = getvid()
            VID_MAP[view['id']] = view
            x = view.get('x', 0)
            y = view.get('y', 0)
            width = view.get('width', 0)
            height = view.get('height', 0)

            # Apply screen scale
            x *= screen_scale
            y *= screen_scale
            width *= screen_scale
            height *= screen_scale

            view['absolute_frame'] = {'x': x, 'y': y, 'width': width, 'height': height}

            # Calculate the absolute center point
            center_x = x + width / 2
            center_y = y + height / 2
            view['absolute_center'] = {'x': center_x, 'y': center_y}

            for key in ['name', 'value', 'label', 'text']:
                if key in view:
                    view[key] = str(view[key]) # Why are they possibly not a string?

            # Process subviews recursively
            for subview in view.get('subviews', []):
                process_view(subview)

        # Process the UI elements
        process_view(uielements)

        return uist, VID_MAP

    @time_consumed
    def getui(self):
        uielements = self.appium.get_page_source()
        screen_scale = 2 # self.gbscript.exports_sync.getscale() # TODO: is this stuck if app is not foreground?
        
        import json, xmljson
        from lxml.etree import fromstring
        xml = fromstring(uielements.encode('utf-8'))
        uielements = json.loads(json.dumps(xmljson.badgerfish.data(xml)))

        try:
            uielements = uielements['AppiumAUT']['XCUIElementTypeApplication']
        except:
            ...
        
        assert uielements['@type'] == 'XCUIElementTypeApplication', "Illegal Appium UI page source"
        
        uist = {'elements': uielements, 'screenscale': screen_scale}

        return self.getui_raw(uist)

    @staticmethod
    @time_consumed
    def post_process_ui(uielements, base64_screenshot):
        icon_like = []

        max_id = 0
        def extract_views(view, parent):
            subviews = []

            nonlocal max_id
            max_id = max(max_id, view['id'])

            FIELDS = ['id', 'type', 'name', 'absolute_frame', 'enabled', 'visible', 'accessible', 'index']
            myview = {k: view[k] for k in FIELDS if k in view}

            # for subview in view.get('subviews', []):
            #     if (subview := extract_views(subview, myview)) is not None:
            #         subviews.extend(subview) # Don't do any optimization (for benchmarking)
            
            myview['subviews'] = subviews

            #return [myview] # Don't do any optimization (for benchmarking)

            if myview.get('name', '') == 'splash_ad':
                myview['name'] = '' # This confuses LLM

            # Keep value only if different
            if 'value' in view and ('name' not in view or view['name'] != view['value']):
                myview['value'] = view['value']
            
            if abs(myview['absolute_frame']['width'] - myview['absolute_frame']['height']) < max(20, 0.2 * min(myview['absolute_frame']['width'], myview['absolute_frame']['height'])):
                if myview['type'] == 'XCUIElementTypeOther' or (myview['type'] == 'XCUIElementTypeStaticText' and not myview.get('value', '').strip() and not myview.get('name', '').strip()):
                    myview['type'] = 'XCUIElementTypeIcon'
                icon_like.append(myview)

            # Naming convention
            myview['frame_box'] = myview['absolute_frame']
            myview['_absolute_frame'] = myview['absolute_frame']
            #del myview['absolute_frame']
            x, y, width, height = myview['frame_box']['x'], myview['frame_box']['y'], myview['frame_box']['width'], myview['frame_box']['height']
            myview['frame_box'] = {'top_left': {'x': x, 'y': y}, 'right_bottom': {'x': x + width, 'y': y + height}, 'width': width, 'height': height}
            del myview['frame_box']

            for subview in view.get('subviews', []):
                if (subview := extract_views(subview, myview)) is not None:
                    subviews.extend(subview)

            # Suppress scroll bars
            if myview['type'] == 'XCUIElementTypeOther' and any(myview.get('name', '').startswith(prefix) for prefix in ['Vertical scroll bar, ', 'Horizontal scroll bar, ', '水平滚动条, ', '垂直滚动条, ']):
                return None
            
            # Suppress empty window
            if myview['type'] == 'XCUIElementTypeWindow' and len(subviews) == 0:
                return None

            # Remove overflow (TODO: not considering scrollable)
            if myview['_absolute_frame']['x'] > BaseUI.get_frame(uielements)['width'] or myview['_absolute_frame']['y'] > BaseUI.get_frame(uielements)['height']:
                return None

            empty_view = {'subviews': [], 'type': '', 'id': 0, 'index': 0, 'accessible': True, 'enabled': True, 'visible': True}

            # Suppress useless views
            if myview['type'] in ['XCUIElementTypeOther', 'XCUIElementTypeStaticText'] and parent and json.dumps(myview | empty_view, sort_keys=True, indent=0) == json.dumps(parent | empty_view, sort_keys=True, indent=0):
                return subviews
            
            empty_view = {'subviews': [], 'id': 0, 'index': 0, 'accessible': True, 'enabled': True, 'visible': True}

            # Suppress duplicate views
            if parent and json.dumps(myview | empty_view, sort_keys=True, indent=0) == json.dumps(parent | empty_view, sort_keys=True, indent=0):
                return subviews

            # Merge single child
            if myview['type'] == 'XCUIElementTypeOther' and len(subviews) == 1 and len(subviews[0].get('subviews', [])) == 0:
                return [myview | subviews[0]]
            
            # Suppress empty size
            if myview['absolute_frame']['width'] == 0 or myview['absolute_frame']['height'] == 0:
                return subviews

            return [myview]

        merged = extract_views(uielements, None)[0]

        #return merged, BaseUI.get_vid_map(merged) # Don't do any optimization (for benchmarking)

        # Suppress XCUIElementType and sort subviews by x-axis (left-to-right)
        def traverse(view):
            if view['type'].startswith('XCUIElementType'):
                view['type'] = view['type'][len('XCUIElementType'):]
            # Split some grids for sorting
            view['subviews'].sort(key=lambda x: (BaseUI.get_frame(x)['y'] // 100, BaseUI.get_frame(x)['x'] // 100, BaseUI.get_frame(x)['y'] // 10, BaseUI.get_frame(x)['x'] // 10, BaseUI.get_frame(x)['y'], BaseUI.get_frame(x)['x']))

            for subview in view.get('subviews', []):
                traverse(subview)

            # Remove subviews with same frame, keeping the first occurrence
            seen_frames = set([(0, 0, 0, 0)])
            filtered_subviews = []
            for subview in view['subviews']:
                frame_tuple = tuple(BaseUI.get_frame(subview).values())
                if frame_tuple not in seen_frames:
                    seen_frames.add(frame_tuple)
                    filtered_subviews.append(subview)
                else:
                    filtered_subviews.extend(subview['subviews'])
            view['subviews'] = filtered_subviews

            # Such merge doesn't make sense (ABANDONED)
            # # Find the maximum area of absolute frame
            # max_frame = None
            # max_area = 0
            # for subview in view['subviews']:
            #     frame = BaseUI.get_frame(subview)
            #     area = frame['width'] * frame['height']
            #     if max_frame is None or area > max_area:
            #         max_frame = frame
            #         max_area = area
            # # If all frames is within the max_frame
            # for subview in view['subviews']:
            #     frame = BaseUI.get_frame(subview)
            #     if frame['x'] < max_frame['x'] or frame['y'] < max_frame['y'] or frame['x'] + frame['width'] > max_frame['x'] + max_frame['width'] or frame['y'] + frame['height'] > max_frame['y'] + max_frame['height']:
            #         break
            # else:
            #     view['_mark_for_merge'] = False
        traverse(merged)

        # Suppress single child
        def traverse1(view):
            for subview in view.get('subviews', []):
                traverse1(subview)
            if len(view['subviews']) == 1 or view.get('_mark_for_merge', False):
                view.pop('_mark_for_merge', None)
                subviews = []
                for view1 in view['subviews']:
                    subviews.extend(view1['subviews'])
                    for key in ['type', 'name', 'value', 'label', 'text']:
                        if key in view1:
                            if key not in view:
                                view[key] = view1[key]
                            else:
                                if isinstance(view[key], str):
                                    view[key] = [view[key]]
                                if isinstance(view1[key], str):
                                    view1[key] = [view1[key]]
                                view[key] = view[key] + [v1k for v1k in view1[key] if v1k not in view[key]]
                    # Suppress duplicated type
                    if 'Other' in view['type'] and len(view['type']) > 1:
                        view['type'] = [type for type in view['type'] if type != 'Other']
                    if 'StaticText' in view['type'] and len(view['type']) > 1:
                        view['type'] = [type for type in view['type'] if type != 'StaticText']
                    if len(view['type']) == 1:
                        view['type'] = view['type'][0]
                view['subviews'] = subviews
        traverse1(merged)

        # Reordering helps LLM to learn the pattern
        max_id = 0
        VID = 0
        def traversex(view):
            nonlocal VID, max_id
            VID += 1
            view['_id'] = view['id']
            view['id'] = VID
            if view['type'] == 'Other':
                view['type'] = 'Frame' # attempt to make llm more focused
            max_id = max(max_id, VID)
            for key in ['type', 'name', 'value', 'label', 'text']:
                if key in view and isinstance(view[key], list):
                    view[key] = ' / '.join(view[key])
            for subview in view.get('subviews', []):
                traversex(subview)
        traversex(merged)

        # CNN classification for icons
        from cnn_cls import EfficientNetClient
        from utils import crop_image
        for view in icon_like:
            if '_id' in view:   # not being removed
                frame = BaseUI.get_frame(view)
                if frame['x'] + frame['width'] > BaseUI.get_frame(merged)['width'] or frame['y'] + frame['height'] > BaseUI.get_frame(merged)['height']:
                    # overflow, skip
                    continue
                icon = crop_image(base64_screenshot, frame['x'], frame['y'], frame['width'], frame['height'])
                icon_label, confidence = EfficientNetClient.classify(icon)
                if confidence > 0.5:
                    view['icon_label'] = icon_label

        # OCR to find any potential text in the screenshot
        from paddle_cls import PaddleOCRClient
        ocr = PaddleOCRClient()
        ocr_result = ocr.ocr(base64_screenshot)
        all_suitable_same = None
        ocr_result = [result for result in ocr_result if result[5] > 0.8]
        for result in ocr_result:
            (x, y, width, height, text, conf) = result
            suitable_element, depth, min_area = BaseUI.find_suitable_element(merged, x, y, width, height)
            if suitable_element and all_suitable_same is not False:
                all_suitable_same = suitable_element if all_suitable_same is None or suitable_element['id'] == all_suitable_same['id'] else False
            text_normalize = lambda text: text.lower().replace(' ', '').replace('\n', '').replace('\t', '').replace('\r', '').strip()
            text_compare = lambda text1, text2: text_normalize(text1 if isinstance(text1, str) else ' '.join(text1)) in text_normalize(text2 if isinstance(text2, str) else ' '.join(text2))
            label_match = lambda element, text: any(k in element and text_compare(text, element[k]) for k in ['name', 'value', 'lable', 'text'])
            if suitable_element and not label_match(suitable_element, text) and \
                    not any(label_match(child, text) for child in suitable_element.get('subviews', [])):
                # Match first level subviews (why child may be a bit larger than parent?)
                suitable_element['ocr_text'] = (suitable_element.get('ocr_text', '') + ' ' + text).strip()
        
        if all_suitable_same and len(ocr_result) > 1:
            # No UI element found, manually append
            all_suitable_same.pop('ocr_text', None)
            for result in ocr_result:
                (x, y, width, height, text, conf) = result
                max_id += 1
                all_suitable_same['subviews'].append({'ocr_text': text, 'absolute_frame': {'x': x, 'y': y, 'width': width, 'height': height}, 'id': max_id, 'type': 'OCRElement', 'subviews': []})

        return merged, BaseUI.get_vid_map(merged)


# Deprecated
class FridaUI(BaseUI):
    def __init__(self, vars):
        (self.gbscript, ) = vars

    @classmethod
    def create_ui(cls, vars):
        return cls(vars)

    def getui(self):
        uist = self.gbscript.exports_sync.getui()
        
        uielements = uist['elements']
        screen_scale = uist['screenscale']

        VID = 0
        def getvid():
            nonlocal VID
            VID += 1
            return VID
        VID_MAP = {}
        
        def process_view(view):
            view['id'] = getvid()
            VID_MAP[view['id']] = view
            frame = view.get('absolute_frame', {})
            x = int(frame.get('x', 0))
            y = int(frame.get('y', 0))
            width = int(frame.get('width', 0))
            height = int(frame.get('height', 0))

            # Apply screen scale
            x *= screen_scale
            y *= screen_scale
            width *= screen_scale
            height *= screen_scale

            view['absolute_frame'] = {'x': x, 'y': y, 'width': width, 'height': height}

            # Calculate the absolute center point
            center_x = x + width // 2
            center_y = y + height // 2
            view['absolute_center'] = {'x': center_x, 'y': center_y}

            # Check if the view is possibly visible and clickable
            alpha = view.get('alpha', 1.0)
            hidden = view.get('hidden', False)
            userInteractionEnabled = view.get('userInteractionEnabled', True)
            opaque = view.get('opaque', True)

            # Convert properties to appropriate types
            alpha = float(alpha) if isinstance(alpha, (int, float, str)) else 1.0
            hidden = bool(hidden) if isinstance(hidden, bool) else False
            userInteractionEnabled = bool(userInteractionEnabled) if isinstance(userInteractionEnabled, bool) else True
            opaque = bool(opaque) if isinstance(opaque, bool) else True

            # Determine visibility and clickability
            is_visible = (alpha > 0) and not hidden and opaque
            is_clickable = is_visible and userInteractionEnabled

            view['is_visible'] = is_visible
            view['is_clickable'] = is_clickable

            # Process subviews recursively
            for subview in view.get('subviews', []):
                process_view(subview)

        # Process the UI elements
        process_view(uielements)

        return uist, VID_MAP
    
    @staticmethod
    def post_process_ui(uielements, base64_screenshot):
        def extract_views(view):
            subviews = []

            FIELDS = ['id', 'class', 'text', 'absolute_frame', 'index', 'type', 'name', 'value']#, 'alpha', 'userInteractionEnabled', 'hidden', 'opaque']
            myview = {k: view[k] for k in FIELDS if k in view}

            for subview in view.get('subviews', []):
                subviews.append(extract_views(subview))

            myview['subviews'] = subviews
            
            return myview
        
        uielements = extract_views(uielements)

        return uielements, BaseUI.get_vid_map(uielements)


