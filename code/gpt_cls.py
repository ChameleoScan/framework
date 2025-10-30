### Configurations
YOUR_API_KEY_HERE = 'YOUR_API_KEY_HERE'

import copy
from typing import Dict, List, Literal, Optional, Union
from pydantic import BaseModel, Field
from enum import Enum
import openai
import json

from utils import time_consumed, token_record

import os
#os.environ['HTTP_PROXY'] = 'socks5://127.0.0.1:1099'
#os.environ['HTTPS_PROXY'] = 'socks5://127.0.0.1:1099'

import logging
# Configure logging
logger = logging.getLogger(__name__)
logging.getLogger("openai").setLevel(logging.ERROR)
logging.getLogger("httpx").setLevel(logging.ERROR)
logging.getLogger("httpcore").setLevel(logging.ERROR)


class UIElementType(str, Enum):
    BUTTON = 'Button'
    TEXT_BUTTON = 'TextButton'
    ICON_BUTTON = 'IconButton'
    INPUT_TEXT = 'InputText'
    CHECKBOX = 'Checkbox'
    RADIO = 'Radio'
    DROPDOWN = 'Dropdown'
    OTHER_INTERACTABLE = 'OtherInteractable'
    TEXT_ONLY = 'TextOnly'
    ICON_ONLY = 'IconOnly'

class UIElement(BaseModel):
    id: int = Field(
        ...,
        description="Unique identifier aligning UI elements precisely between JSON data and screenshots."
    )
    ui_type: UIElementType = Field(
        ...,
        description="Explicit UI element category (e.g., 'Button', 'InputText'). All clickable button-like items inferred clearly as 'Buttons', text fields as 'InputText'."
    )
    description: str = Field(
        ...,
        description="Clear inferred purpose or expected click behavior of this UI element based on UI context."
    )
    text: str = Field(
        ...,
        description="Complete text displayed within the UI element, including input values and labels. Use ' / ' delimiter for multiple texts."
    )
    clickability: float = Field(
        ...,
        description="Confidence (0.0–1.0) of this element’s clickability; higher scores indicate strongly clickable."
    )
    location: str = Field(
        ...,
        description="Exact UI position clearly described (e.g., 'Top-left corner', 'Middle button in bottom navigation')."
    )

class UIAds(BaseModel):
    is_ad_topmost: bool = Field(
        ...,
        description="True if a clearly visible, urgent advertisement fully covers the main UI and requires immediate handling."
    )
    is_ad_closeable: bool = Field(
        ...,
        description="True if the advertisement can clearly be dismissed via a close button or skip option."
    )
    ad_close_button_id: int = Field(
        ...,
        description="Exact UI element ID of the close or skip button (e.g., icon labeled 'X', '关闭', '跳过') for this advertisement; '0' if not available."
    )

class UIView(BaseModel):
    hint_elements: List[UIElement] = Field(
        ...,
        description="All relevant non-interactive or semi-interactive UI elements (labels, images, static texts) providing contextual hints."
    )
    action_elements: List[UIElement] = Field(
        ...,
        description="All explicitly interactive UI elements (buttons, icons, input fields, checkboxes, radio buttons, dropdown menus)."
    )
    description: str = Field(
        ...,
        description="Concise top-down, left-right description clearly summarizing UI layout, structural components (title, sidebar, footer), and main interaction purpose."
    )
    is_alert_topmost: bool = Field(
        ...,
        description="True if an urgent, fully visible alert popup overlays UI, requiring immediate user attention."
    )
    ads: Optional[UIAds] = Field(
        ...,
        description="Detailed information regarding topmost advertisement overlay, if present."
    )
    feedback_message: str = Field(
        ...,
        description="Explicitly describe any visible feedback, error, or status messages (alerts, toast messages, loading indicators); empty string if none."
    )
    match_rate: float = Field(
        ...,
        description="Match accuracy (0.0–1.0) of identified UI elements to provided screenshot; below 0.5 indicates significant mismatch requiring re-synchronization."
    )

    @property
    def elements(self) -> List[UIElement]:
        return self.hint_elements + self.action_elements



class UserActionType(BaseModel):
    """Base class for all user action types."""
    pass

class UserActionTypeNone(UserActionType):
    type: Literal["none"] = Field(
        ...,
        description="Perform no action at this moment, waiting for UI changes or loading to complete."
    )

class UserActionTypeClick(UserActionType):
    type: Literal["click"] = Field(
        ...,
        description="Click or tap interaction performed on a specific UI element."
    )
    element_id: int = Field(
        ...,
        description="The exact ID of the UI element targeted for this click action."
    )
    times: int = Field(
        ...,
        description="Number of consecutive clicks/taps to be performed on the UI element."
    )

class UserActionTypeInput(UserActionType):
    type: Literal["input"] = Field(
        ...,
        description="Enter provided text into a specific UI text field element."
    )
    element_id: int = Field(
        ...,
        description="The exact ID of the UI text input element targeted."
    )
    text: str = Field(
        ...,
        description="The precise text string to input into the targeted UI text field."
    )

class UserActionTypeRestart(UserActionType):
    type: Literal["restart"] = Field(
        ...,
        description="Restart the app entirely due to UI being unresponsive, stuck, or obstructed by uncloseable advertisements."
    )

class UserActionTypeCompleted(UserActionType):
    type: Literal["completed"] = Field(
        ...,
        description="The main task has been conclusively finished; no further actions are required."
    )


class UserActionStep(BaseModel):
    reasoning: str = Field(
        ...,
        description="Brief and clear justification explaining the necessity of this action step."
    )
    target_element_id: int = Field(
        ...,
        description="ID of the UI element targeted by this step (use '0' if no specific element, '-1' if element is not currently available)."
    )
    reason_of_element: str = Field(
        ...,
        description="Brief rationale for selecting this specific UI element for the action; leave empty if no element involved."
    )
    completeness_check: str = Field(
        ...,
        description=(
            "Explicit logical check ensuring the proposed action step is fully valid, consistent, and logically complete. "
            "Clearly state if any prerequisite step or condition is incomplete or missing, and finish it in next action step. "
        )
    )
    action: Union[
        UserActionTypeNone,
        UserActionTypeClick,
        UserActionTypeInput,
        UserActionTypeRestart,
        UserActionTypeCompleted
    ] = Field(
        ...,
        description="Concrete user action to be executed in this step, clearly defined by action type and parameters."
    )

class UserActionSummary(BaseModel):
    ui_summary: str = Field(
        ...,
        description="Concise yet precise description of the current UI page and its main interaction purpose (e.g., 'A login screen titled '登录以继续' with two text fields, prompting the user to submit credentials.')."
    )
    action_summary: str = Field(
        ...,
        description="Brief, present-tense summary of planned actions clearly stating what actions will be executed, the rationale behind them, and input texts if applicable."
    )

class UserAction(BaseModel):
    past_action_summary: str = Field(
        ...,
        description="Clear summary of previous UI pages visited and actions executed leading up to the current state."
    )
    recent_repeat_action: str = Field(
        ...,
        description="Description of the most recent action series repeated multiple times, the reason for repetition, and expected outcomes; leave empty if none."
    )
    recent_repeat_count: int = Field(
        ...,
        description="Count indicating how many times the most recent action series was consecutively repeated (resets upon new attempts)."
    )
    page_visited_summary: str = Field(
        ...,
        description="Clearly state if the current page was previously visited and outline prior interactions or attempts made on it."
    )
    page_semantic: str = Field(
        ...,
        description="Concise summary of the UI page's purpose and relevance to the main task, based on layout, content, and UI descriptions."
    )
    explore_ui_or_not_reason: str = Field(
        ...,
        description="Justification on whether to continue directly with the main task via current UI interactions, or pause the main task temporarily to explore UI semantics further."
    )
    subtask: str = Field(
        ...,
        description="Clear, concise, actionable sub-task within the current UI that directly supports progression towards the main goal."
    )
    reasoning: str = Field(
        ...,
        description="Explicit reasoning demonstrating why the identified sub-task is crucial to achieving the main task, considering the history of actions performed."
    )
    actions: List[UserActionStep] = Field(
        ...,
        description="Ordered sequence of immediate next actions required to progress towards the completion of the defined sub-task."
    )
    summary: UserActionSummary = Field(
        ...,
        description="Compact summaries describing current UI context (ui_summary) and a brief yet precise plan of proposed actions (action_summary)."
    )

class UserAction(BaseModel):
    past_action_summary: str = Field(..., description="A concise summary of all UI pages visited and actions performed of state transition before this point.")
    recent_repeat_action: str = Field(..., description="A concise summary of the most recently (from at most last 6 actions) repeated series of actions, as well as the reason for repeating and the expected result; otherwise empty.")
    recent_repeat_count: int = Field(..., description="The number of times the most recently (from at most last 6 actions) repeated series of actions has been performed. Some other attempts will reset the recent repeat count.")
    page_visited_summary: str = Field(..., description="Indicates whether this page has been visited before in the action history. If visited, includes details on previous interactions or attempts made on this page to inform further decisions.")
    explore_ui_or_not_reason: str = Field(..., description="Given past action history and the current UI page, decide whether to progress towards the main task by interacting with current UI page, or temporarily ignore the main task to focus on the UI page's semantics and its purpose.")
    page_semantic: str = Field(..., description="A concise summary of the current UI page's semantics and its purpose based on description and layout, while describing whether it is possibly related to the main task or not.")
    subtask: str = Field(..., description="A short, clear, undone, non-repetitive, non-redundant small sub-task in the current UI page to possibly move forward towards the main task.")
    reasoning: str = Field(..., description="A clear explanation of why this sub-task is essential towards the main task based on the previous action history.")
    
    actions: List[UserActionStep] = Field(..., description="An ordered list of next consecutive user actions to perform.")
    summary: UserActionSummary = Field(..., description="Brief statements summarizing the current UI (ui_summary) and proposed actions (action_summary).")


class DetectMaskResult(BaseModel):
    result: Literal["Yes", "No"] = Field(
        ...,
        description=(
            "'Yes' if the screenshot and UI text clearly demonstrate functionality entirely unrelated to "
            "the appstore description (e.g., hidden or illegal features). "
            "'No' if the app behavior is consistent or potentially consistent with its official description."
        )
    )
    reasoning: str = Field(
        ...,
        description=(
            "Detailed and logical justification for determining whether the app's runtime UI aligns "
            "or conflicts with its appstore description, explicitly mentioning observed UI text or elements."
        )
    )
    score: float = Field(
        ...,
        description=(
            "Confidence level (0.0–1.0) indicating how strongly the screenshot and runtime UI text "
            "are unrelated to the appstore description. Scores closer to 1.0 indicate strong contradictions."
        )
    )
    ads: Literal["Yes", "No"] = Field(
        ...,
        description=(
            "'Yes' if marketing or promotional content (advertisements, pop-ups) significantly obscures "
            "the app’s main functionality, complicating the evaluation; 'No' otherwise."
        )
    )



class TriggerProbabilities(BaseModel):
    open: float = Field(..., 
        description="Probability of triggers based on opening the app (0.0 - 1.0). Examples include simply opening the app, reopening after a restart or waiting for 10s.")
    condition: float = Field(..., 
        description="Probability of triggers based on specific times or locations (0.0 - 1.0). Examples include opening at midnight or in a specific country.")
    operation: float = Field(..., 
        description="Probability of triggers based on specific user operation (0.0 - 1.0). Examples include tapping bottom of the page 10 times, or interacting with specific UI elements 6 times quickly.")
    trigger: float = Field(..., 
        description="Probability of triggers based on specific text input actions (0.0 - 1.0). Examples include entering specific text in feedback fields or search bars.")
    # mixed: float = Field(..., description="Probability of mixing based on the aforementioned four triggering modes (0.0 - 1.0).")

class TriggerField(BaseModel):
    time: Optional[str] = Field(
        None, 
        description="Specific time condition required to trigger hidden functionality, e.g., 'midnight to 1 AM'.")
    location: Optional[str] = Field(
        None, 
        description="Specific geographic or network condition required, e.g., 'China', 'VPN disabled'.")
    wait: Optional[int] = Field(
        None, 
        description="Mandatory waiting time (in seconds) after opening or restarting the app to activate hidden functions.")
    click_location: Optional[str] = Field(
        None, 
        description="Specific UI location or element requiring consecutive clicks, e.g., 'homepage icon', 'blank space'.")
    click_time: Optional[int] = Field(
        None, 
        description="Number of required consecutive clicks on a specified UI location or element.")
    text_location: Optional[str] = Field(
        None, 
        description="UI element or input field where specific textual content must be entered, e.g., 'feedback form', 'search box'.")
    text_content: str = Field(
        None, 
        description="Exact textual content required to trigger hidden functionality, e.g., '5201080', '666', 'ys777'.")
    confidence: float = Field(
        ...,
        description="Confidence score (0.0 - 1.0) indicating the reliability of identified trigger fields."
    )

class TriggerResponse(BaseModel):
    analysis_metadata: str = Field(
        ...,
        description="Systematically analyze the provided app metadata (app profile, user reviews) to find any suspicious traces. (As much detail as possible)"
    )
    analysis_similarity: str = Field(
        ...,
        description="Systematically analyze whether this app is similar to existing patterns in any of bundle id, name, description, app profile, user reviews. (As much detail as possible)"
    )
    is_mask_package: Literal['Yes', 'No', 'Unable to determine'] = Field(
        ...,
        description=(
            "Determines whether the app is a disguised application containing hidden functionalities not matching its official description. "
            "'Yes': confirmed disguise; 'No': confirmed legitimate; 'Unable to determine': insufficient evidence or ambiguity."
        )
    )
    is_mask_package_probability: float = Field(
        ...,
        description=(
            "Confidence score (0.0–1.0) reflecting how certain it is that the app is disguised, "
            "based on user reviews, appstore description, and observed behaviors."
        )
    )
    is_mask_package_valid: float = Field(
        ...,
        description=(
            "Likelihood (0.0–1.0) that the disguised functionalities are still operational and accessible. "
            "Lower values suggest that hidden features may have been disabled or are no longer valid."
        )
    )
    trigger_probabilities: TriggerProbabilities = Field(
        ...,
        description=(
            "Probabilities (0.0–1.0) for each trigger type, including app open patterns, time/location conditions, "
            "specific operations (click behaviors), and special inputs. Multiple triggers may coexist."
        )
    )
    inferred_triggers: List[TriggerField] = Field(
        ...,
        description=(
            "List of inferred possible triggers. Each item contains necessary details (time, location, wait duration, "
            "click location/count, specific text input) for activating hidden functionalities. Provide 'None' if a field is undetermined."
        )
    )



class GPTClient:
    API_KEY = YOUR_API_KEY_HERE
    API_URL = ''

    def __init__(self, api_key=API_KEY, api_url=API_URL):
        self.api_key = api_key
        self.client = openai.Client(api_key=api_key)

    @time_consumed
    def predict_task(self, comment_list: list, appstore_info: dict):
        """
        Try to predict the trigger task from app's info and comments.

        Args:
            comment_list (list): The comment list of current app.
            appstore_info (dict): The information in appstore. Containing category, name and description.

        Returns:
            list: a possibility list.

        """

        def comment_preprocessing(comment_list: list[str]) -> str:
            max_len = 80
            total_max_len = 8000
            result_comment_list = []
            for comment in comment_list:
                c = comment[0] + ' : ' + comment[1]
                c = c.replace('\n', ';')
                if len(c) > max_len:
                    result_comment_list.append(c[:max_len-3] + '...')
                else:
                    result_comment_list.append(c)
            result = '\n'.join(result_comment_list)
            if len(result) > total_max_len:
                result = result[:total_max_len]
            return result
        

        messages = [
            {
                "role": "system",
                "content": [
                    {
                        "type": "text",
                        "text": (
                            "Your task is to accurately detect whether an app is disguised, meaning its actual functionalities differ significantly "
                            "from those described in the app store. Based on provided appstore metadata, screenshots, and user comments, perform the following:\n\n"
                            
                            "Step 1: Determine whether the app is disguised:\n"
                            "- Answer 'Yes' if evidence clearly indicates hidden functionalities (e.g., mismatch between described and actual functions, user comments mentioning triggers, required input phrases, bundle id domain/app profile similar to known exemplars, or unusual app behaviors).\n"
                            "- Answer 'No' if the app functions exactly as described, with no discrepancies or user-reported anomalies.\n"
                            "- Answer 'Unable to determine' if evidence is ambiguous, insufficient, or obscured by unrelated marketing/promotional elements.\n\n"
                            
                            "Step 2: Assign a probability (0.0–1.0) reflecting confidence that the app is disguised (higher if user comments explicitly indicate triggers or hidden behaviors).\n\n"
                            
                            "Step 3: Assign a probability (0.0–1.0) indicating if the hidden functionality is still accessible (lower if user comments suggest triggers no longer work, higher if recent comments indicate active use).\n\n"
                            
                            "Step 4: Clearly identify trigger probabilities:\n"
                            "- Open app trigger ([1]): App transforms automatically after opening, multiple openings, or after waiting (e.g., '重启自动变身', '打开后等10秒').\n"
                            "- Condition-based trigger ([2]): Requires specific geographic location or time conditions (e.g., '凌晨打开', '中国地区', '关闭VPN').\n"
                            "- Operation-based trigger ([3]): Requires specific user interaction, like repeated clicks or watching ads (e.g., '连续点击5次', '点击空白10下', '点击图标3次').\n"
                            "- Text-based trigger ([4]): Requires entering specific text in designated fields (e.g., '问题反馈输入666', '建议反馈输入5201080').\n\n"

                            "Provide a confidence (0.0–1.0) for each trigger type. Multiple trigger methods can coexist.\n\n"

                            "Step 5: Clearly infer possible trigger details based on evidence. Include the following if explicitly mentioned or strongly implied by user comments:\n"
                            "- Specific time (e.g., '0-1点')\n"
                            "- Specific geographic/location conditions (e.g., '中国', '关闭VPN')\n"
                            "- Waiting time after app launch (e.g., '10秒')\n"
                            "- Click locations and counts (e.g., '点击屏幕底部5次')\n"
                            "- Exact input texts and their fields (e.g., '在意见反馈处输入5201080')\n\n"

                            "Step 6: Handling Fields:\n"
                            "- If 'text_content' (specific input content) is unknown, DO NOT generate a trigger involving text input.\n"
                            "- Do NOT write explanations or descriptions inside empty fields.\n"
                            "- If the exact location of text input ('text_location') is unknown, you may possibly assume a common field (e.g., '意见反馈', '问题反馈', '文本输入框') if ever mentioned; otherwise explicitly leave unknown.\n\n"
                            
                            "Use provided comments for inference:\n"
                            "Example [Automatic transformation - wait 10s]:\n"
                            "[['打开', '打开等待'], ['提示更新闪退', '一直提示更新，无论更新与不更新都闪退，无法观看'], ['更新', '更新']]\n\n"

                            "Example [Clicking locations - click donuts 5 times]:\n"
                            "[['点击', '点击5次'], ['甜甜圈', '一直点'], ['打开', '打开']]\n\n"

                            "Example [Clicking locations - click chat icon 3 times]:\n"
                            "[['点击', '点三下'], ['聊天', '聊天'], ['一直点', '一直点'], ['右上角', '聊天']]\n\n"
                            
                            "Example [Specific text input trigger - two 5201080 or 666 possible]:\n"
                            "[['求暗号', '打不开'], ['口令', '五二0零八零 数字'], ['口令', '5⃣️2⃣️o1⃣️o8⃣️o'], ['提交完进不去啊', '口令，我爱零你零八零'], ['666', '666'], ['太良心的软件 孩子很喜欢！！！！', '太好用了 孩子很喜欢520！！！！我真的会爱上1080遍！！！！'], ['666', '666']]\n\n"

                            "Example [Specific text input trigger - two 橘子真甜 or 666 possible]:\n"
                            "[['橘子真甜', '橘子真甜'], ['橘子真甜', '橘子真甜'], ['提交', '口令'], ['666', '666'], ['橘子真甜', '橘子真甜'], ['橘子真甜', '橘子真甜']]\n\n"

                            "Example [Spatiotemporal conditions - in China with VPN off]:\n"
                            "[['无广子', '关闭 V*N'], ['定位中国', '定位中国'], ['打不开', '允许连接网络权限']]\n\n"

                            "Example [Submit text in feedback - 777ys]:\n"
                            "Name: 追击点数\n"
                            "Bundle ID: com.xingqi.fenh.dice (same family or template reuse)\n\n"

                            "Example text input triggers: 666, ys777, 大耳朵图图, 大马猴, 你好123, 变美要自信, 我爱中国, 999999, 5201080, 小柿子, 蒙太奇, 和气生财, 好运家, 龙年大吉, 八方来财, 鸭梨鸭梨, 继续加油, 新年快乐, 好久不见, 完美工具, c1, c7, and so on.\n"
                            
"\n\nAdditional EXEMPLARS:\n"
"""
{"name":"变色找找看","bundleid":"com.jide.jide.bianse","method_family":"submit_text","ui_entry":"首页·意见反馈","keyword":"小柿子","aux_actions":[],"confidence":0.93,"evidence":["‘意见反馈写小柿子就可以看’","‘填小柿子没用啊’"]}
{"name":"柠檬猜色（极速版）","bundleid":"com.oese.lcnglu.mosor","method_family":"submit_text","ui_entry":"我的→给点建议","keyword":"小柿子","aux_actions":[],"confidence":0.86,"evidence":["多条‘小柿子’短评","‘怎么变身’求助"]}
{"name":"极速找形","bundleid":"com.jide.jide.xingzhuang","method_family":"submit_text","ui_entry":"首页·问题反馈","keyword":"小柠檬","aux_actions":[],"confidence":0.9,"evidence":["‘小柠檬没反应’","‘怎么提交意见反馈’"]}
{"name":"方阵成语","bundleid":"com.wxj.zyzs.chengyu","method_family":"submit_text","ui_entry":"问题反馈","keyword":"小柠檬","aux_actions":[],"confidence":0.91,"evidence":["‘激活暗号小柠檬’","‘小柠檬用不了啊’"]}
{"name":"变美小帮手","bundleid":"app.kan.bianmei","method_family":"submit_text","ui_entry":"设置→反馈意见","keyword":"变美要自信","aux_actions":[],"confidence":0.88,"evidence":["多条‘变美要自信’","‘点提交没反应/广告多’"]}
{"name":"美味直达","bundleid":"com.food.radar","method_family":"submit_text","ui_entry":"首页搜索栏","keyword":"黄龙痛饮","aux_actions":["press_search"],"confidence":0.84,"evidence":["‘口令没用/没反应’","‘输入后404 loading’"]}
{"name":"Full Record - Recording tools","bundleid":"tools.matter.me","method_family":"submit_text","ui_entry":"“+”新建→标题/内容","keyword":"完美工具","aux_actions":["restart_many_times"],"confidence":0.87,"evidence":["‘完美工具很好用’","‘要多试几次/黑屏/投屏问题’"]}
{"name":"小幸运收藏","bundleid":"com.wucheng.LuckyMoment","method_family":"submit_text","ui_entry":"首页添加→第一栏","keyword":"幸运","aux_actions":["save"],"confidence":0.6,"evidence":["无显著短评，仅流程描述"]}
{"name":"心口默默算","bundleid":"com.feige.com.xink","method_family":"submit_text","ui_entry":"首页·提交建议","keyword":"5201080","aux_actions":[],"confidence":0.92,"evidence":["‘口令：5201080’直述","‘提交完进不去/网络错误’"]}
{"name":"旧车新生","bundleid":"com.Match.Motor","method_family":"submit_text","ui_entry":"搜索框","keyword":"龙腾虎跃","aux_actions":["press_enter"],"confidence":0.86,"evidence":["‘现在是龙腾虎跃’","‘求暗号/打不开’"]}
{"name":"高质家政","bundleid":"com.elite.HomeApp","method_family":"submit_text","ui_entry":"搜索栏","keyword":"当日口令(如龙威虎震/龙举云兴等)","aux_actions":["press_search"],"confidence":0.84,"evidence":["‘今日口令是什么’密集","多条具体口令被点名"]}
{"name":"微光-人人都是主题设计师","bundleid":"cn.onedayapp.onedayNovelVip","method_family":"submit_text","ui_entry":"我的→帮助反馈→意见反馈","keyword":"我爱中国","aux_actions":["restart_app"],"confidence":0.9,"evidence":["‘我爱中国’多次出现","‘隐藏模式/广告时间’讨论"]}
{"name":"行票易记","bundleid":"com.pz.xz.piao","method_family":"submit_text","ui_entry":"右上角！","keyword":"小柿子","aux_actions":["reopen_after_crash"],"confidence":0.85,"evidence":["多条‘小柿子’","‘闪退/打不开’共现"]}
{"name":"智棋计时","bundleid":"com.ybspace.kateworld.qibang","method_family":"submit_text","ui_entry":"底部·问题反馈弹窗","keyword":"777ys","aux_actions":["reopen_after_crash"],"confidence":0.91,"evidence":["‘进去点问题反馈 777ys 就可以了’","多条‘777ys’确认"]}
{"name":"发艺简约","bundleid":"com.nuode.isteward.fayue","method_family":"submit_text","ui_entry":"首页·问题反馈","keyword":"777ys","aux_actions":[],"confidence":0.82,"evidence":["‘777ys.pro’提及","‘骗子/片源下架’两极评价"]}
{"name":"快降夺冠","bundleid":"com.feige.com.diaoyuan","method_family":"submit_text","ui_entry":"问题反馈","keyword":"777ys","aux_actions":[],"confidence":0.83,"evidence":["‘问题反馈无法输入’","‘追剧神器’正向回声"]}
{"name":"黄瓜视频线索组","bundleid":"me.RampExteriorWall.app","method_family":"clipboard_text","ui_entry":"首次启动→允许粘贴","keyword":"剪贴板命中特定串(如“黄瓜视频”或同批密文)","aux_actions":[],"confidence":0.78,"evidence":["评论点名‘黄瓜视频’与粘贴权限"]}
{"name":"Quantusimu","bundleid":"com.QQjruheLo.NTC","method_family":"clipboard_text","ui_entry":"首次启动→允许粘贴→获取最新版本","keyword":"长串密文+代码=BGZ0853","aux_actions":["wait_loading"],"confidence":0.8,"evidence":["一致‘更新卡0%/需切换网络’反馈"]}
{"name":"EvacuationWidth","bundleid":"com.EvacuationWidth.SanShu","method_family":"clipboard_text","ui_entry":"首次启动→允许粘贴→获取最新版本","keyword":"#iPhone#…代码=BGZ0853","aux_actions":["wait_loading"],"confidence":0.8,"evidence":["与Quantusimu同模板·同抱怨"]}
{"name":"正旋压降计算","bundleid":"com.zongde.chaolai","method_family":"clicks_plus_text","ui_entry":"计算→输入框1","keyword":"999999","aux_actions":["click_3_times"],"confidence":0.72,"evidence":["‘999999+计算3次’指引","评论多为广告/关不掉"]}
{"name":"加班调休阁","bundleid":"com.example.overtimeRecord","method_family":"clicks_plus_text","ui_entry":"请假→标题","keyword":"999999","aux_actions":["click_n_times"],"confidence":0.8,"evidence":["‘请假标题6个9点添加记录即可’","‘广告关不掉/闪退’"]}
{"name":"水电气综合记录表","bundleid":"com.example.surfaceManager","method_family":"clicks_plus_text","ui_entry":"水表→添加记录→表记读数","keyword":"999999","aux_actions":["click_3_times","save"],"confidence":0.78,"evidence":["示例族‘999999+点击’","评论指向广告/投诉"]}
{"name":"山茶录","bundleid":"com.example.pinChaMan","method_family":"clicks_plus_text","ui_entry":"右下角＋→茶名","keyword":"999999","aux_actions":["click_3_times","add"],"confidence":0.75,"evidence":["同家族触发语义","有‘横屏反向/输入法问题’反馈"]}
{"name":"交织钱保宝","bundleid":"com.example.walletManager","method_family":"submit_text","ui_entry":"右下角＋→交易名/金额","keyword":"999999","aux_actions":["add"],"confidence":0.76,"evidence":["‘999999后添加交易’说明","‘横屏只支持一侧’反馈"]}
{"name":"四叶运动手册","bundleid":"com.example.runShengccai","method_family":"submit_text","ui_entry":"锻炼→＋→三处输入","keyword":"999999","aux_actions":["add","restart_app"],"confidence":0.77,"evidence":["‘添加后提示激活成功重启’","评论多为‘广告/诱导订购’"]}
{"name":"好记性密码管理","bundleid":"com.exa.passwordTool","method_family":"clicks_plus_text","ui_entry":"添加新密码→ServiceName","keyword":"222222","aux_actions":["click_3_times","restart_app"],"confidence":0.8,"evidence":["‘投屏失效/广告关不掉’","‘显示无网络’与激活后语境匹配"]}
{"name":"马松阁","bundleid":"com.berlari.tool","method_family":"clicks_plus_text","ui_entry":"设置→反馈内容","keyword":"222222","aux_actions":["click_3_times"],"confidence":0.73,"evidence":["‘白屏/连不上网’与触发后状态同现"]}
{"name":"铜排电路多样计算","bundleid":"com.jingchao.tanhui","method_family":"clicks_plus_text","ui_entry":"计算→铜排载流量→第1框","keyword":"999999","aux_actions":["click_3_times","restart_app"],"confidence":0.79,"evidence":["‘广告关不掉/横屏方向反了’","与触发后界面一致的抱怨"]}
{"name":"工况/筒径流量求知","bundleid":"com.deshi.qingchu","method_family":"clicks_plus_text","ui_entry":"标准工况流量计算→第1框","keyword":"999999","aux_actions":["click_3_times","restart_app"],"confidence":0.78,"evidence":["多条‘666’保护/刷屏","并有‘看广告/诈骗’投诉"]}
{"name":"土壤洞察向导","bundleid":"com.mudi.land","method_family":"clicks_plus_text","ui_entry":"对流换热系数→第1框","keyword":"999999","aux_actions":["click_3_times","restart_app"],"confidence":0.77,"evidence":["‘出现激活成功重启’描述","评论‘纯看广告’与之同批"]}
{"name":"微工具：剪贴板批","bundleid":"com.MYDETAR.www","method_family":"clipboard_text","ui_entry":"首次启动→允许粘贴","keyword":"批量密文/口令(同批)","aux_actions":["toggle_airplane_mode_if_stuck"],"confidence":0.7,"evidence":["‘停在获取最新版本’","‘飞行模式切换可缓解’"]}
{"name":"AI剧影小帮手","bundleid":"jiuxon.com.ShijuAiCoperAssiant","method_family":"submit_text","ui_entry":"首页空白栏→输入后点AI帮手","keyword":"壳儿","aux_actions":["reenter_app"],"confidence":0.62,"evidence":["少量‘广告关不掉/投屏项’","口令提示较弱，保守标注"]}
{"name":"印章-文件盖章生成器与管理器","bundleid":"Aoxin.yinzhang.com","method_family":"submit_text","ui_entry":"三条杠→意见反馈","keyword":"和气生财","aux_actions":[],"confidence":0.85,"evidence":["多条‘和气生财/龙年大吉’短评","‘必须看广告’与触发后体验一致"]}


POSSIBLE RELATIONS (BUNDLE ID SUBDOMAIN => TRANSFORMATION METHOD: KEYWORDS TO INPUT):
zw.sz => 小柠檬
yunti.zzm => 666
qiu.okw.opg => 666
kj.wenz => 小柠檬
hy.buto => 小柿子
com.example => 999999+点击
dz.spd => 小柿子
ddy.shuziMiaowen => 皮皮真不错|野原新之助
cz.dbi => 777ys
com.xingqi.fenh => 777ys
com.pz.xz => 888
com.cor.zx => xyz|mmm
birdcard.cai => 爱其意


ADDITIONAL COMPACT DECISION SCHEMA:
If reviews show “feedback/problem/contact” + an exact repeated word/phrase → method=submit-text (or method=searchbar-submit if “search bar” is explicit); keyword=that phrase; add post_action=restart or auto_crash_then_reopen when stated.
If “clipboard/allow paste/代码/#iPhone#” → method=clipboard-text; token=given long code; preconditions: allow paste + network; often reopen.
If instructions mention “click N times” after entering a number → method=submit-text + repeat-clicks; keyword=digits; clicks=N; post_action=restart.
If both selecting an option and typing a word are required → method=select-option + submit-text; include option + keyword.
Add preconditions if reviews/descriptions mention network permission or a time window.
If only generic negatives (ads/white screen) and no concrete keyword/path → no trigger inferred.
"""
"\n\n"

                            #"Only infer a text input trigger if multiple comments explicitly repeat the same unusual phrase or number sequence.\n"
                            "Positively infer a text input trigger if comments indicate unusually repeating phrases or number sequences, that is abrupt or similar to known examples.\n"
                            "Positively infer operation-based trigger if comments indicate suspicious click operations, such as clicking on a specific icon multiple times.\n"
                            "Similar BundleID / Domain Strings / App Theme may share the same keyword-based transformation method as examples. Positively suggest them if no other method is found.\n"
                            "Clearly specify any uncertainties by marking fields as 'None' if not confidently determined.\n\n"

                            "Ensure all provided examples guide your inference clearly and accurately. Do not deviate from the output schema or include unsupported assumptions."
                        ),
                    },
                ],
            },
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": "Appstore metadata:\n\n",
                    },
                    {
                        "type": "text",
                        "text": 
                            f"bundle id: {appstore_info['bundle_id']}\n" +
                            f"name: {appstore_info['name']}\n" + 
                            f"category: {appstore_info['category']}\n" + 
                            f"description: {appstore_info['description']}\n\n"
                    },
                    {
                        "type": "text",
                        "text": "Comments (provided in format 'Title: Content'):\n\n",
                    },
                    {
                        "type": "text",
                        "text": comment_preprocessing(comment_list),
                    },
                ],
            }
        ]

        logger.debug(f"User reviews: {comment_preprocessing(comment_list)}")

        # Generate the response schema from the Pydantic model
        response_format = TriggerResponse

        # Call the OpenAI API
        try:
            completion  = self.client.beta.chat.completions.parse(
                model="gpt-4o-2024-11-20",
                messages=messages,
                temperature=0.1,
                n=1,
                response_format=response_format,
            )

            # Extract the response content
            result = completion.choices[0].message.parsed

            logger.debug(
                f"Predict_Task: token consumed: "
                f"{completion.usage.prompt_tokens} + {completion.usage.completion_tokens} "
                f"= {completion.usage.total_tokens}"
            )

            token_record('predict_task', completion.usage.prompt_tokens, completion.usage.completion_tokens)

            return result
        except Exception as e:
            logger.error(f"Error during OpenAI API call: {e}")
            raise e

    @staticmethod
    def _render_trigger_response(trigger_field: TriggerField) -> str:
        '''动态生成触发任务的描述，拼接非空字段以生成完整的自然语言任务说明'''
        components = []
        if trigger_field.time:
            components.append(f"在'{trigger_field.time}'时间")
        if trigger_field.location:
            components.append(f"在'{trigger_field.location}'地理条件")
        if trigger_field.wait:
            components.append(f"打开APP并等待'{trigger_field.wait}'秒")
        if trigger_field.click_location or trigger_field.click_time:
            components.append(f"在'{getattr(trigger_field, 'click_location', None) or '{任意}'}'位置连续点击'{str(getattr(trigger_field, 'click_time', None) or 1)}'下")
        if trigger_field.text_location or trigger_field.text_content:
            components.append(f"在'{getattr(trigger_field, 'text_location', None) or '{文本输入框}'}'位置输入'{getattr(trigger_field, 'text_content', None) or '{潜在触发词}'}'内容")
        return "，".join(components) + "，完成触发；结合不同角度以及页面语义进行探索（优先特别注意 functional icons、menu、tab bars、my center、feedback、search、settings、preferences、personal、about、chat、message 等功能）" if components else ""
    
    @time_consumed
    def detect_mask(self, base64_screenshot: str, text_list: List[str], appstore_info: dict):
        """
        Check whether the screenshot and text conflict with the information in appstore.

        Args:
            base64_screenshot (str): The screenshot encoded in base64.
            text_list (List[str]): The text list in current UI.
            appstore_info (dict): The information in appstore. Containing category, name and description.

        Returns:
            str: the result.
        """
        # Prepare the messages for the chat completion
        # Construct the content as a list of content parts

        messages = [
            {
                "role": "system",
                "content": [
                    {
                        "type": "text",
                        "text": (
                            "Your task is to determine if the actual runtime UI of an app (as shown in the provided screenshot and accompanying texts) "
                            "is clearly unrelated or contradictory to the official description provided on the app store.\n\n"
                            
                            "Step-by-Step Evaluation Criteria:\n\n"

                            "Step 1: Evaluate whether the screenshot and UI text directly conflict with the appstore description:\n"
                            "- Output 'Yes' only if:\n"
                            "  • The app clearly provides features or content totally unrelated to its official description.\n"
                            "  • The screenshot explicitly indicates switching or redirecting to another unrelated app or website (e.g., browser with unrelated content).\n"
                            "  • The UI explicitly mentions unlocking hidden modes or additional behaviors, such as phrases: '开启隐藏模式', '解锁所有功能', '输入暗号解锁', '输入享受完整功能'.\n\n"
                            
                            "- Output 'No' only if:\n"
                            "  • UI screens clearly still loading, incomplete, or temporarily blank (e.g., blank screens, loading spinners, logos only without content).\n"
                            "  • Generic UI pages without explicit evidence of hidden functionality (e.g., simple login screens, feedback pages, settings pages, input screens without explicit trigger instructions).\n"
                            "  • Unclear UI pages with least elements but not showing any suspicious clues about hidden functionality (e.g., an input field without any description, an image without any description).\n"
                            "  • The app’s runtime UI matches, or potentially matches, its described functionalities from the app store.\n"
                            "  • Observed discrepancies originate solely from user-entered text rather than built-in app behaviors.\n\n"

                            "- Otherwise, output 'Yes' or 'No' whichever best matches the conditions.\n\n"

                            "Step 2: Provide detailed reasoning:\n"
                            "- Explicitly reference exact UI texts or visual elements from the screenshot supporting your conclusion.\n"
                            "- Highlight critical discrepancies or confirmations, clearly connecting them to the provided appstore description.\n\n"
                            
                            "Step 3: Assign a confidence score (0.0–1.0):\n"
                            "- 0.8–1.0: Strong, explicit contradiction (e.g., hidden mode clearly mentioned).\n"
                            "- 0.5–0.7: Moderate contradiction (e.g., suspicious but not explicitly stated).\n"
                            "- Below 0.5: Weak or no contradiction.\n\n"
                            
                            "Step 4: Clearly identify if advertisements or promotions significantly obscure UI evaluation:\n"
                            "- Output 'Yes' if promotional pop-ups or ads heavily obscure the UI, making accurate evaluation difficult.\n"
                            "- Output 'No' otherwise.\n\n"
                            
                            "Examples:\n\n"
                            
                            "[Example 1 - Clear contradiction (Output: Yes)]:\n"
                            "  Appstore Description: 'An educational app for kids to learn math.'\n"
                            "  Screenshot/UI text: A pop-up, '点击此处进入隐藏模式', '请输入口令解锁所有影片'.\n"
                            "  Reasoning: 'UI explicitly mentions unlocking hidden video features unrelated to math education.'\n"
                            "  Score: 0.95\n"
                            "  Ads: No\n\n"
                            
                            "[Example 2 - No contradiction (Output: No)]:\n"
                            "  Appstore Description: 'A fitness app tracking daily steps and calories.'\n"
                            "  Screenshot/UI text: A page with lists and categories, '今日步数: 1024', '消耗热量: 320千卡'.\n"
                            "  Reasoning: 'Runtime UI fully matches described fitness tracking features.'\n"
                            "  Score: 0.1\n"
                            "  Ads: No\n\n"
                            
                            "[Example 3 - Ads obscuring evaluation (Output: No, Ads: Yes)]:\n"
                            "  Appstore Description: 'News aggregator providing global headlines.'\n"
                            "  Screenshot/UI text: An overlaying ad, '立即下载精彩游戏', '广告倒计时: 30秒'.\n"
                            "  Reasoning: 'Advertisements completely obscure underlying content; unable to assess actual functionality clearly.'\n"
                            "  Score: 0.4\n"
                            "  Ads: Yes\n\n"

                            "[Example 4 - Clear contradiction (Output: Yes)]:\n"
                            "  Appstore Description: 'A tool for calculating resistance in an electric circuit.'\n"
                            "  Screenshot/UI text: Blank page, '大鱼影视', '在线观看'.\n"
                            "  Reasoning: 'UI is generic but runtime texts uncover the hidden functionality of watching movies.'\n"
                            "  Score: 0.8\n"
                            "  Ads: No\n\n"

                            "Strictly adhere to the output schema. Make no assumptions beyond provided evidence and examples. "
                            "If uncertain, reflect that clearly in reasoning and score."
                        ),
                    },
                ],
            },
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": "Appstore metadata:\n\n",
                    },
                    {
                        "type": "text",
                        "text": (
                            "Name: " + appstore_info['name'] + "\n"
                            "Category: " + appstore_info['category'] + "\n"
                            "Description: " + appstore_info['description'].replace('\n', ' ') + "\n"
                        )
                    },
                    {
                        "type": "text",
                        "text": "\n\nPart of UI runtime texts:\n",
                    },
                    {
                        "type": "text",
                        "text": '\n'.join(text_list) + "\n\n",
                    },
                    {
                        "type": "text",
                        "text": "Screenshot image for reference:\n",
                    },
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": f"data:image/png;base64,{base64_screenshot}"
                        },
                    },
                ],
            }
        ]

        # Generate the response schema from the Pydantic model
        response_format = DetectMaskResult

        # Call the OpenAI API
        try:
            completion  = self.client.beta.chat.completions.parse(
                model="gpt-4o-2024-11-20",
                messages=messages,
                temperature=0.1,
                n=1,
                response_format=response_format,
            )

            # Extract the response content
            result = completion.choices[0].message.parsed

            logger.debug(f"Detect_Mask: text_list: {text_list}")
            
            logger.debug(
                f"Detect_Mask: token consumed: "
                f"{completion.usage.prompt_tokens} + {completion.usage.completion_tokens} "
                f"= {completion.usage.total_tokens}"
            )

            token_record('detect_mask', completion.usage.prompt_tokens, completion.usage.completion_tokens)

            logger.debug(f"Detect_Mask: result: {result}")

            return result
        except Exception as e:
            logger.error(f"Error during OpenAI API call: {e}")
            raise e

    
    @staticmethod
    def _get_slim_ui(ui: UIView) -> str:
        """
        Convert UIView to a "slim" text so GPT can focus on essential data
        """
        slim_ui = []
        for element in ui.elements:
            # Decide category
            if element.ui_type == UIElementType.INPUT_TEXT:
                category = "InputText"
            elif element.ui_type == UIElementType.ICON_BUTTON:
                category = "IconButton"
            elif element.ui_type == UIElementType.CHECKBOX:
                category = "Checkbox"
            elif element.ui_type == UIElementType.RADIO:
                category = "Radio"
            elif element.ui_type == UIElementType.DROPDOWN:
                category = "Dropdown"
            elif element.ui_type in [
                UIElementType.BUTTON,
                UIElementType.TEXT_BUTTON,
                UIElementType.OTHER_INTERACTABLE
            ] or element.clickability > 0.5:
                category = "Button"
            elif element.ui_type == UIElementType.TEXT_ONLY:
                category = "Text"
            elif element.ui_type == UIElementType.ICON_ONLY:
                category = "Image"
            else:
                # Fallback logic
                category = "Text" if element.text.strip() else "Image"
            
            slim_ui.append({'id': element.id, 'category': category, 'description': element.description, 'text': element.text, 'location': element.location})
        
        slim_ui_text = json.dumps(slim_ui, indent=2, ensure_ascii=False)
        return slim_ui_text

    @staticmethod
    def _get_action_history(action_history: List[str]) -> str:
        """
        Convert action history to a text
        """
        action_history_text = "[*] 1. Launch the application from SpringBoard\n" + "\n".join([("[*] " if any(s in action.lower() for s in ['. restart ', 'restart the app']) else "") + f"{i}. {action}" for i, action in enumerate(action_history, start=2)])
        return action_history_text

    @time_consumed
    def analyze_action(self, analyzed_ui: UIView, task: str, action_history: List[str], recent_repeat_action: str = '', recent_repeat_count: int = 0) -> UserAction:
        """
        Analyzes the current UI (analyzed_ui), the user's 'task', and 'action_history', 
        then instructs GPT to propose a valid UserAction. This method is constructed 
        similarly to analyze_screenshot(), making an API call and parsing GPT output 
        as a UserAction according to a given schema.
        """

        slim_ui_text = self._get_slim_ui(analyzed_ui)
        action_history_text = self._get_action_history(action_history)
        
        # Build system and user messages
        messages = [
            {
                "role": "system",
                "content": [
                    {
                        "type": "text",
                        "text": (
                            "Your task is to propose clear and actionable user interactions based on the current UI state, historical actions, and the main task provided.\n\n"

                            "Detailed Steps and Restrictions:\n\n"

                            "Step 1: Fully assess the current UI:\n"
                            "- Clearly summarize the page’s primary function and interaction points (buttons, input fields, tabs).\n"
                            "- Handle urgent UI states first (alerts, pop-ups, advertisements). Ads or alerts must be closed/skipped immediately if possible, unless they are mentioned in the main task.\n"
                            "- If topmost UI elements are non-dismissible, suggest app restart.\n\n"

                            "Step 2: Evaluate the action history:\n"
                            "- Clearly summarize previously visited pages and performed actions.\n"
                            "- Explicitly indicate repeated action sequences (more than twice), and clearly state alternatives if repetition yields no results.\n\n"

                            "Step 3: Identify a precise sub-task:\n"
                            "- Clearly define a concise, actionable sub-task advancing toward the main goal.\n"
                            "- Explicitly verify and clearly state completeness or incompleteness of all required conditions (e.g., all inputs completed, required navigational steps previously done, prerequisite UI interactions).\n"
                            "- Provide explicit reasoning why this sub-task is critical based on prior interactions and current UI context, and necessary for the logical flow toward task completion.\n\n"

                            "Step 4: Propose detailed next actions:\n"
                            "- Actions must be sequential, logically coherent, fully justified, and explicitly validated through the completeness check (including UI element IDs).\n"
                            "- Directly issue 'Input' actions instead of clicks for text entry fields to minimize interactions.\n"
                            "- If no immediate actions are feasible, propose a 'None' action clearly stating the reason (e.g., loading, waiting for UI update).\n"
                            "- Mark task completion explicitly when previous actions clearly indicate the goal is achieved.\n\n"

                            "Step 5: Summarize clearly:\n"
                            "- Provide concise UI page summary clearly describing current context and interaction purpose.\n"
                            "- Provide a precise action summary clearly stating planned actions and rationale, including exact input texts if applicable.\n\n"

                            "Strictly follow provided output schema and examples. Ensure actions are practical, relevant, and clearly explained."
                        )
                    }
                ],
            },
            # 2. System message (context injection): Task
            {
                "role": "system",
                "content": [
                    {
                        "type": "text",
                        "text": "The user's task to accomplish: \n",
                    },
                    {
                        "type": "text",
                        "text": task + "\n\n",
                    },
                ]
            },
            # 3. User message: Slim UI data
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": (
                            "Current UI summary:\n" + analyzed_ui.description + "\n\n"
                            "The UI has a visible feedback/status/error message: " + analyzed_ui.feedback_message if analyzed_ui.feedback_message else "" + "\n\n"
                            "The UI has an alert or pop-up, which should be handled before doing anything else.\n\n" if analyzed_ui.is_alert_topmost else ""
                            "The UI has an urgent topmost overlaying advertisement, which must be handled before doing anything else.\n\n" if analyzed_ui.ads and analyzed_ui.ads.is_ad_topmost and analyzed_ui.ads.is_ad_closeable and analyzed_ui.ads.ad_close_button_id > 0 else ""
                            # If not closeable, the Bot is not able to handle it.
                            "\n"
                        )
                    },
                    {
                        "type": "text",
                        "text": "Current UI view:\n"
                    },
                    {
                        "type": "text",
                        "text": slim_ui_text + "\n\n"
                    },
                    {
                        "type": "text",
                        "text": "Previous action history:\n" + action_history_text + "\n\n" + ((
                            "The recent action series '" + recent_repeat_action + "' has been repeated " + str(recent_repeat_count) + " times.\n"
                            "Do not repeat this action series again. Actively seek and propose alternatives.\n\n"
                        ) if recent_repeat_count >= 3 else "")
                    },
                    {
                        "type": "text",
                        "text": "The user's task (again) is to:\n",
                    },
                    {
                        "type": "text",
                        "text": task + "\n\n",
                    },
                    {
                        "type": "text",
                        "text": "Now start proposing the next user action(s) to move toward completing the task.",
                    },
                ],
            },
        ]

        # We want GPT to parse the final response as a UserAction
        response_format = UserAction

        # Token counting for demonstration/logging
        from tiktoken import encoding_for_model
        enc = encoding_for_model("gpt-4o")

        #text_tokens = sum(len(enc.encode(content["text"])) for msg in messages for content in msg["content"] if "text" in content)
        #logger.debug(f"Estimated request tokens: {text_tokens}")
        #logger.debug(f"Input prompt: %s", '\n'.join([content["text"] for msg in messages for content in msg["content"] if "text" in content]))

        try:
            completion = self.client.beta.chat.completions.parse(
                model="gpt-4o-2024-11-20",
                messages=messages,
                temperature=0.1,
                n=1,
                response_format=response_format,
            )

            # Parsed result is a valid UserAction object
            result = completion.choices[0].message.parsed

            logger.debug(
                f"Analyze_Action: token consumed: "
                f"{completion.usage.prompt_tokens} + {completion.usage.completion_tokens} "
                f"= {completion.usage.total_tokens}"
            )

            token_record('analyze_action', completion.usage.prompt_tokens, completion.usage.completion_tokens)

            return result

        except Exception as e:
            logger.error(f"Error during OpenAI API call for analyze_action: {e}")
            # Return a fallback "none" action if GPT fails
            raise e
        
    @time_consumed
    def analyze_screenshot(self, base64_screenshot: str, ui_runtime_elements_json: dict, focus_ads: bool = False) -> UIView:
        """
        Analyzes a screenshot and extracts significant and clickable UI elements.

        Args:
            base64_screenshot (str): The screenshot encoded in base64.
            ui_runtime_elements_json (dict): JSON dictionary of extracted UI runtime elements.

        Returns:
            UIView: An object containing significant and clickable UI elements with descriptions,
                    visibility, and confidence of clickability.
        """
        # Ensure ui_runtime_elements_json is a dictionary
        if isinstance(ui_runtime_elements_json, str):
            try:
                ui_runtime_elements = json.loads(ui_runtime_elements_json)
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON input: {e}")
                return None
        else:
            ui_runtime_elements = copy.deepcopy(ui_runtime_elements_json)
        
        # Remove all attributes starting with '_'
        def traverse(view):
            for k, v in view.copy().items():
                if k.startswith('_'):
                    del view[k]
                elif isinstance(v, dict):
                    traverse(v)
                elif isinstance(v, list):
                    for item in v:
                        if isinstance(item, dict):
                            traverse(item)
        traverse(ui_runtime_elements)

        from utils import _dump_xml

        # Prepare the messages for the chat completion
        # Construct the content as a list of content parts

        messages = [
            {
                "role": "system",
                "content": [
                    {
                        "type": "text",
                        "text": (
                            "Your task is to analyze provided runtime UI XML data and corresponding screenshot, carefully matching and classifying UI elements to clearly generate a structured UIView object.\n\n"

                            "Detailed Steps and Exact Restrictions:\n\n"

                            "Step 1: Carefully match XML element IDs and bounding boxes precisely with visible screenshot elements:\n"
                            "- Discard any XML elements that clearly do not match or are not fully visible in the screenshot.\n"
                            "- Prioritize essential functional elements clearly needed for interaction (close buttons, search icons, navigation buttons, input fields).\n"
                            "- Ignore native OS-level status/navigation bars or keyboards.\n\n"

                            "Step 2: Classify UI elements explicitly into two categories:\n"
                            "- 'hint_elements': Clearly non-interactive or semi-interactive hints (labels, static texts, descriptive images).\n"
                            "- 'action_elements': Explicitly interactive elements (buttons, text fields, checkboxes, radios, dropdowns, clickable icons).\n\n"

                            "Step 3: Explicitly identify and describe advertisements and alerts:\n"
                            "- Clearly detect topmost overlay advertisements requiring immediate dismissal; identify their exact close buttons clearly labeled (e.g., 'X', '关闭', '跳过').\n"
                            "- Clearly detect any fully visible, topmost urgent alerts requiring immediate action.\n"
                            "- If an ad or alert is partially visible or non-urgent (small corner overlay), clearly mention it but mark as non-topmost.\n\n"

                            "Step 4: Clearly describe UI layout and function concisely:\n"
                            "- Provide a clear, structured top-down, left-right UI description explicitly mentioning UI components (e.g., header bar, sidebar, footer menu, content area).\n"
                            "- Explicitly note any feedback, status, or error messages clearly visible in UI; leave empty if none.\n\n"

                            "Step 5: Clearly calculate UI-to-screenshot matching accuracy:\n"
                            "- Provide a precise matching accuracy (0.0–1.0). Scores below 0.5 explicitly indicate severe mismatches, recommending re-synchronization.\n\n"

                            "Strictly follow the output schema and clearly adhere to provided examples. "
                            "Do not infer elements or UI functions beyond visible evidence."
                        )
                    },
                ],
            },
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": "Below is the UI runtime elements XML:\n",
                    },
                    {
                        "type": "text",
                        #"text": json.dumps(ui_runtime_elements, indent=2, ensure_ascii=False, sort_keys=True),
                        "text": _dump_xml(ui_runtime_elements),
                        # Does some indent makes LLM better to understand the hierarchy?
                    },
                    {
                        "type": "text",
                        "text": "\n\nBelow is the screenshot image for reference:\n",
                    },
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": f"data:image/png;base64,{base64_screenshot}"
                        },
                    },
                    {
                        "type": "text",
                        "text": (
                            "\n\n"
                            "" if not focus_ads else "Advertisements seem to exist in the page. Identify any topmost alerts as advertisements if they do have a close button.\n\n"
                            "Now start matching elements by their XML ID and bounding box within the screenshot to infer meaning."
                        ),
                    }
                ],
            },
        ]

        # Generate the response schema from the Pydantic model
        response_format = UIView

        # Calculate token count for request
        from tiktoken import encoding_for_model
        enc = encoding_for_model("gpt-4o")
        
        # Count tokens in text portions
        #text_tokens = text_tokens = sum(len(enc.encode(content["text"])) for msg in messages for content in msg["content"] if "text" in content)
        
        # Add tokens for image (estimated as per OpenAI docs)
        #image_tokens = 85 + 170 * 4  # 85 tokens for image metadata + 4 tiles
        #total_tokens = text_tokens + image_tokens
        
        #logger.debug(f"Estimated request tokens: {total_tokens}")
        #logger.debug(f"Input prompt: %s", '\n'.join([content["text"] for msg in messages for content in msg["content"] if "text" in content]))

        # Call the OpenAI API
        try:
            completion = self.client.beta.chat.completions.parse(
                model="gpt-4o-2024-11-20", 
                messages=messages,
                temperature=0.1,
                n=1,
                response_format=response_format,
            )

            # Extract the response content
            result = completion.choices[0].message.parsed
            
            # Get token count from completion response
            logger.debug(f"Analyze_UI: token consumed: {completion.usage.prompt_tokens} + {completion.usage.completion_tokens} = {completion.usage.total_tokens}")
            if completion.usage.prompt_tokens >= 16000:
                logger.warning(f"Analyze_UI: Used {completion.usage.prompt_tokens} tokens for prompt >= 16k")
            
            token_record('analyze_ui', completion.usage.prompt_tokens, completion.usage.completion_tokens)

            return result
        except Exception as e:
            logger.error(f"Error during OpenAI API call: {e}")
            raise e
    
    @DeprecationWarning
    def ocr(self, base64_image: str):
        """
        Extracts text from an image using OCR (Optical Character Recognition).

        Args:
            base64_image (str): The image encoded in base64.

        Returns:
            str: The extracted text from the image.
        """
        messages = [
            {
                "role": "system",
                "content": [
                    {
                        "type": "text",
                        "text": (
                            "You are an advanced OCR (Optical Character Recognition) and UI analysis assistant. "
                            "Your task is to analyze App UI screenshots, identify key UI elements, and provide detailed information about each detected component. "
                            "The screenshots are divided into a visible grid system, where each grid cell is labeled with a unique index. "
                            "For each detected UI element: "
                            "1. Specify whether it is text, an icon, or a clickable element. "
                            "2. Provide the Minimum Bounding Rectangle (MBR) indices, defined by the top-left and bottom-right grid indices, to encapsulate the element within the minimal number of grid cells. "
                            "Ensure that the MBR is strictly minimal and contains only the detected element, without expanding it to include surrounding areas. "
                            "3. Include any detected text associated with the element. "
                            "4. Provide an assumed description of the element's function or role in the UI. "
                            "5. Assess the likelihood of the element being clickable and include a confidence score for this assessment. "
                            
                        )
                    },
                ],
            },
            {
                "role": "user",
                "content": [
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": f"data:image/png;base64,{base64_image}"
                        },
                    },
                ],
            }
        ]

        class BoundingBox(BaseModel):
            left_top_idx: int = Field(..., description="The index of the top-left grid.")
            right_bottom_idx: int = Field(..., description="The index of the bottom-right grid.")

        class UIElement(BaseModel):
            ui_type: Literal['Button', 'TextButton', 'IconButton', 'InputText', 'Checkbox', 'Radio', 'Dropdown', 'TextOnly', 'IconOnly']
            description: str = Field(..., description="The description (assumed effect in context) of the UI element.")
            text: str = Field(..., description="Current text content of the UI element.")
            visibility: bool = Field(..., description="The actual visibility of the UI element in the screenshot.")
            confidence: float = Field(..., description="The assumed confidence of clickability of the UI element. (0.0 - 1.0)")
            bounding_box: BoundingBox = Field(..., description="The bounding box indices of the UI element.")

        class UIView(BaseModel):
            elements: List[UIElement] = Field(..., description="List of all (especially those significant and clickable) UI elements.")

        response_format = UIView

        try:
            completion = self.client.beta.chat.completions.parse(
                model="gpt-4o",
                messages=messages,
                temperature=0,
                n=1,
                response_format=response_format,
            )

            result = completion.choices[0].message.parsed

            return result
        except Exception as e:
            logger.error(f"Error during OpenAI API call: {e}")
            raise e
    

    @DeprecationWarning
    def fix_ocr(self, base64_img: str, ocr_result: dict):
        """
        Extract possibly significant or clickable elements from OCR results with absolute coordinates.

        Args:
            base64_img (str): The image encoded in base64.
            ocr_result (JSON dict): The OCR results to be fixed.

        Returns:
            dict: A dictionary containing significant and clickable UI elements with descriptions,
                  visibility, and confidence of clickability.
        """
        messages = [
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": (
                            "Analyze the attached OCR results and screenshot to identify significant and interactable UI elements. "
                            "The OCR results contain extracted text and bounding box coordinates for each text element. "
                            "For each text element, infer and classify it as a UI element by assuming its type (e.g., Button, TextButton, IconButton, etc.) based on its label, context, or icon proximity."
                            "(Preferably assume type as Button or another clickable type.)"
                            "Include attributes such as ID, assumed type, assumed description, current text content, and confidence of clickability. "
                            "Additionally, provide a high-level description of the overall UI view and any alert or feedback messages visible in the screenshot. "
                            "Focus only on elements corresponding to the indices (IDs) in the OCR JSON and those fully or partly visible in the screenshot. "
                            "Ignore elements that are not listed in the OCR JSON or are entirely out of view."
                        )
                    },
                    {
                        "type": "text",
                        "text": "Below are the OCR results:",
                    },
                    {
                        "type": "text",
                        "text": json.dumps(ocr_result, indent=0),
                    },
                    {
                        "type": "text",
                        "text": "Below is the screenshot image for reference:",
                    },
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": f"data:image/png;base64,{base64_img}"
                        },
                    },
                ],
            }
        ]
        
        response_format = UIView

        try:
            completion  = self.client.beta.chat.completions.parse(
                model="gpt-4o",
                messages=messages,
                temperature=0.1,
                n=1,
                response_format=response_format,
            )

            result = completion.choices[0].message.parsed

            return result
        except Exception as e:
            logger.error(f"Error during OpenAI API call: {e}")
            raise e

    

