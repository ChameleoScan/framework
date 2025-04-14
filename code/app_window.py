import tkinter as tk
from tkinter import ttk
from PIL import Image, ImageTk
import threading
import time
import queue
import json
import base64
import copy

import logging
logger = logging.getLogger(__name__)

from utils import *

MAX_UI_DIFF_COUNT = 3
MAX_NO_ACTION_COUNT = 3
MAX_STEPS_COUNT = 12

result_callback, step_callback = None, None
get_screenshot, mask_detection, base_ui, base_action = None, None, None, None

class App:
    @classmethod
    def create_window(cls, bind_vars):
        """Bind functions to class variables"""
        global get_screenshot, mask_detection, base_ui, base_action, result_callback, step_callback
        get_screenshot, mask_detection, base_ui, base_action = bind_vars[1:]
        result_callback, step_callback = bind_vars[0]
        root = tk.Tk()
        app = cls(root)
        return root, app

    def __init__(self, root):
        self.root = root
        self.root.title("UI Analyzer")
        self.root.geometry("1600x900")

        # Add flag to control thread execution
        self.running = True

        # Control variables
        self.last_restart = 1
        self.ui_diff_count = 0
        self.no_action_count = 0

        # Is the mask detection triggered?
        self.is_triggered = False
        # Is the task completed?
        self.is_completed = False
        
        # Bind window close event
        self.root.wm_protocol("WM_DELETE_WINDOW", self.on_closing)
        self._close_immediately = False
        self.schedule_close_check()

        # Configure grid weights
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(1, weight=2)
        self.root.grid_columnconfigure(2, weight=1)

        # Create PanedWindow containers
        self.h_paned = ttk.PanedWindow(root, orient=tk.HORIZONTAL)
        self.h_paned.grid(row=0, column=0, columnspan=3, sticky="nsew", padx=5, pady=5)

        # Left frame for screenshot
        self.left_frame = ttk.Frame(self.h_paned, padding=5)
        self.left_frame.grid_rowconfigure(0, weight=1)
        self.left_frame.grid_columnconfigure(0, weight=1)
        self.left_frame.config(width=400)
        self.left_frame.grid_propagate(False)

        # Middle and right container
        self.right_container = ttk.PanedWindow(self.h_paned, orient=tk.HORIZONTAL)

        # Middle frame for tree
        self.middle_frame = ttk.PanedWindow(self.right_container, orient=tk.VERTICAL)
        self.middle_frame.grid_rowconfigure(0, weight=3)
        self.middle_frame.grid_rowconfigure(1, weight=1)
        self.middle_frame.grid_columnconfigure(0, weight=1)
        self.middle_frame.config(width=800)
        self.middle_frame.grid_propagate(False)

        # Right frame for details
        self.right_frame = ttk.PanedWindow(self.right_container, orient=tk.VERTICAL)
        self.right_frame.grid_rowconfigure(0, weight=3)
        self.right_frame.grid_rowconfigure(1, weight=1)
        self.right_frame.grid_columnconfigure(0, weight=1)
        self.right_frame.config(width=400)
        self.right_frame.grid_propagate(False)

        # Add frames to PanedWindows
        self.h_paned.add(self.left_frame, weight=1)
        self.h_paned.add(self.right_container, weight=2)
        
        self.right_container.add(self.middle_frame, weight=2)
        self.right_container.add(self.right_frame, weight=1)

        # Canvas for screenshot
        self.canvas = tk.Canvas(self.left_frame, bg="white", highlightthickness=0)
        self.canvas.grid(row=0, column=0, sticky="nsew")
        self.canvas.bind("<Button-1>", self.on_canvas_click)

        # Add right-click bindings
        self.canvas.bind("<Button-3>", self.show_canvas_menu)
        
        # Create context menus
        self.canvas_menu = tk.Menu(root, tearoff=0)
        self.element_menu = tk.Menu(root, tearoff=0)
        
        # Initialize last right-click position
        self.last_right_click_pos = None
        self.last_right_click_element = None

        # Tree with scrollbar
        tree_frame = ttk.Frame(self.middle_frame)
        tree_frame.grid_columnconfigure(0, weight=1)
        tree_frame.grid_rowconfigure(0, weight=1)
        
        # Configure tree style
        style = ttk.Style()
        style.configure("Treeview", indent=20)  # Increase indentation
        
        self.tree = ttk.Treeview(tree_frame, selectmode="browse", style="Treeview",
                                show="tree")  # Only show tree column, remove headings
        
        # Configure the tree column to expand but allow horizontal scrolling when needed
        self.tree.column("#0", stretch=True, minwidth=2000)  # Allow column to stretch but maintain minimum width
        
        # Vertical scrollbar
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        # Horizontal scrollbar
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        
        # Configure both scrollbars
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Grid layout with both scrollbars
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        
        # Configure tree_frame grid weights to allow scrollbar to show
        tree_frame.grid_rowconfigure(1, weight=0)  # Don't let horizontal scrollbar stretch
        tree_frame.grid_columnconfigure(1, weight=0)  # Don't let vertical scrollbar stretch
        
        self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)
        self.tree.bind("<Button-3>", self.show_tree_menu)

        # Middle bottom text - wrap in a frame
        middle_bottom_frame = ttk.Frame(self.middle_frame)
        middle_bottom_frame.config(height=200)
        middle_bottom_frame.grid_propagate(False)
        self.step_desc = tk.Text(middle_bottom_frame, wrap=tk.WORD)
        vsb_desc = ttk.Scrollbar(middle_bottom_frame, orient="vertical", command=self.step_desc.yview)
        self.step_desc.configure(yscrollcommand=vsb_desc.set)
        self.step_desc.grid(row=0, column=0, sticky="nsew")
        vsb_desc.grid(row=0, column=1, sticky="ns")
        
        # Configure middle_bottom_frame grid
        middle_bottom_frame.grid_columnconfigure(0, weight=1)
        middle_bottom_frame.grid_rowconfigure(0, weight=1)

        # Add to middle paned window
        self.middle_frame.add(tree_frame, weight=3)
        self.middle_frame.add(middle_bottom_frame, weight=1)

        # Right details text - wrap in a frame
        right_top_frame = ttk.Frame(self.right_frame)
        self.details_text = tk.Text(right_top_frame, wrap=tk.WORD)
        vsb_details = ttk.Scrollbar(right_top_frame, orient="vertical", command=self.details_text.yview)
        self.details_text.configure(yscrollcommand=vsb_details.set)
        self.details_text.grid(row=0, column=0, sticky="nsew")
        vsb_details.grid(row=0, column=1, sticky="ns")
        
        # Configure right_top_frame grid
        right_top_frame.grid_columnconfigure(0, weight=1)
        right_top_frame.grid_rowconfigure(0, weight=1)

        # Right bottom text - wrap in a frame
        right_bottom_frame = ttk.Frame(self.right_frame)
        self.ui_desc = tk.Text(right_bottom_frame, height=10, wrap=tk.WORD)
        vsb_elem = ttk.Scrollbar(right_bottom_frame, orient="vertical", command=self.ui_desc.yview)
        self.ui_desc.configure(yscrollcommand=vsb_elem.set)
        self.ui_desc.grid(row=0, column=0, sticky="nsew")
        vsb_elem.grid(row=0, column=1, sticky="ns")
        
        # Configure right_bottom_frame grid
        right_bottom_frame.grid_columnconfigure(0, weight=1)
        right_bottom_frame.grid_rowconfigure(0, weight=1)

        # Add to right paned window
        self.right_frame.add(right_top_frame, weight=3)
        self.right_frame.add(right_bottom_frame, weight=1)

        # Control buttons frame - update grid position
        control_frame = ttk.Frame(root)
        control_frame.grid(row=1, column=0, columnspan=3, pady=5, sticky="ew")
        control_frame.grid_columnconfigure(2, weight=1)  # Make middle column expandable

        # Left-aligned controls
        left_controls = ttk.Frame(control_frame)
        left_controls.grid(row=0, column=0, sticky="w")

        self.auto_refresh = tk.BooleanVar(value=True)
        ttk.Checkbutton(left_controls, text="Auto Refresh", 
                       variable=self.auto_refresh).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(left_controls, text="Manual Refresh",
                  command=self.trigger_refresh).pack(side=tk.LEFT, padx=5)

        self.refresh_label = ttk.Label(left_controls, text="Refreshed 0 seconds ago")
        self.refresh_label.pack(side=tk.LEFT, padx=5)

        # Add a separator
        ttk.Separator(left_controls, orient="vertical").pack(side=tk.LEFT, padx=5)

        self.auto_apply = tk.BooleanVar(value=True)
        ttk.Checkbutton(left_controls, text="Auto Apply",
                       variable=self.auto_apply).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(left_controls, text="Inspect Actions",
                  command=self.trigger_action).pack(side=tk.LEFT, padx=5)

        # Right-aligned status
        self.mask_label = ttk.Label(control_frame, text="Mask Detection: Pending")
        self.mask_label.grid(row=0, column=2, sticky="e", padx=20)

        self.status_label = ttk.Label(control_frame, text="Status: Idle") 
        self.status_label.grid(row=0, column=3, sticky="e", padx=20)

        self.mask_result = None
        self.mask_thread = None

        self.action_dialog = None
        self.is_fetching_ui = False

        # Initialize variables
        self.update_interval = 100  # milliseconds
        self.last_refresh_time = time.time()
        self.scale_factor = 1.0
        self.photo = None
        self.last_screenshot = None  # cached screenshot image data 
        self.org_uist = None         # original ui elements (not being post-processed)
        self.uist = None             # ui elements
        self.org_vid_map = None      # original ui elements (not being post-processed)
        self.vid_map = None          # synchronized with current ui elements
        self.analyzed_ui = None      # analyzed ui elements
        self.actions = None          # actions analyzed for current UI
        self.action_history = []     # history of actions
        self._actions_history = []   # history of analyzed actions
        self.task = 'None'           # task description

        self.skip_steps_by_preprocess = 0 # steps skipped by sync_ui_screenshot preprocessor
        self.ui_change_history = []       # ui history if any change is detected
        
        # Queue for communication between threads
        self.data_queue = queue.Queue()
        self.action_queue = queue.Queue()
        self.is_updating = False

        # Start UI updates in separate thread
        self.check_update()

        # Handle window resize
        self.root.bind("<Configure>", self.on_window_resize)
        self.is_resize_done = True
        
        # Start checking queue periodically
        self.check_queue()
        
        # Start refresh time updater
        self.update_refresh_time()

        # Add instance variables for highlighting
        self.highlight_rect = None
        self.current_element_id = None

        # Add cache-related variables
        self.enable_ui_cache = False  # SETTINGS: Toggle for UI caching
        self.cached_uist = None
        self.cached_analyzed = None

    def set_task(self, task):
        """Set the task description"""
        self.task = task
    
    def close_immediately(self):
        """Close the window immediately by setting flag"""
        self._close_immediately = True
    
    def schedule_close_check(self):
        """Schedule close check"""
        if self._close_immediately:
            self.on_closing()
        else:
            self.root.after(300, self.schedule_close_check)
    
    def assert_running(self):
        """Assert that the window is still running"""
        if not self.running:
            raise Exception("Window is not running")

    def call_blocking(self, func, *args, **kwargs):
        """Call a function in a blocking manner and return its result"""
        result = None
        
        def wrapper():
            nonlocal result
            result = func(*args, **kwargs)
            
        thread = threading.Thread(target=wrapper, daemon=True)
        thread.start()
        
        while True:
            self.root.update()
            if not thread.is_alive() or not self.running:
                break
            time.sleep(0.05)
                
        return result

    def check_update(self):
        """(Loop Schedule) Check if update is needed"""
        if self.running:
            if len(self.action_history) > 3 and all(line.strip().startswith('[*]') for line in base_action._get_action_history(self.action_history).split('\n')[1:][-12:]):
                logger.warning("App continues to restart for more than 3 times, terminating...")
                result_callback(False, False, True)
                if not self._close_immediately:
                    self.on_closing()
                return
            if not self.is_updating and self.auto_refresh.get():
                self.mask_result = self.mask_thread = None
                self.mask_label.config(text="Mask Detection: Pending", foreground="black")
                self.root.after(0, self.trigger_refresh)
            self.root.after(self.update_interval, self.check_update)

    def trigger_refresh(self):
        """Start the UI refreshing process"""
        if self.running and not self.is_updating:
            self.is_updating = True
            threading.Thread(target=self.fetch_ui_data, daemon=True).start()
    
    def trigger_action(self):
        """Start the action analysis process"""
        if self.running and not self.is_fetching_ui and not self.action_dialog:
            threading.Thread(target=self.fetch_action, daemon=True).start()
    
    def trigger_mask(self, final_ui, base64_screenshot):
        """Start the mask detection process"""
        if self.running and not self.mask_thread:
            self.mask_thread = threading.Thread(target=self.fetch_mask, args=(final_ui, base64_screenshot), daemon=True)
            self.mask_thread.start()

    def check_queue(self):
        """(Loop Schedule) Check for completed updates"""
        data = None
        try:
            while True:
                data = self.data_queue.get_nowait()
                if not data == True:
                    self.status_label.config(text="Status: Restarting app")
                    self.action_history.append("The app may have crashed and is not responding. Restart the app.")
                    self._actions_history.append(None)
                    self.call_blocking(base_action.restart_app) # the app may crash
                    self.is_updating = False
                    self.trigger_refresh()
                    continue
                self.update_display()
        except queue.Empty:
            pass
        if data:
            # Trigger action analysis
            self.trigger_action()
            # Trigger mask detection if ads are not detected
            if self.analyzed_ui.ads and self.analyzed_ui.ads.is_ad_topmost and self.analyzed_ui.ads.ad_close_button_id > 0:
                self.mask_label.config(text="Mask Detection: Skip", foreground="black")
            else:
                self.mask_label.config(text="Mask Detection: Waiting", foreground="black")
                self.trigger_mask(self.uist['elements'], base64.b64encode(self.last_screenshot).decode('utf-8'))

        try:
            while True:
                action = self.action_queue.get_nowait()
                if not action == True:
                    self.status_label.config(text="Status: Restarting app")
                    self.action_history.append("The app may have crashed and is not responding. Restart the app.")
                    self._actions_history.append(None)
                    self.call_blocking(base_action.restart_app) # the app may crash
                    self.is_updating = False
                    self.trigger_refresh()
                    continue
                self.update_display()
                self.status_label.config(text="Status: Waiting for user confirmation")
                self.create_action_dialog()
        except queue.Empty:
            pass

        # Schedule next check
        if self.running:
            self.root.after(100, self.check_queue)
    
    def create_action_dialog(self):
        """Create a dialog to confirm the action"""
        # Create dialog window
        self.action_dialog = tk.Toplevel(self.root)
        self.action_dialog.title("Confirm Action")
        self.action_dialog.geometry("600x500")  # Initial size
        
        # Restore previous position if it exists
        if hasattr(self, 'dialog_geometry'):
            self.action_dialog.geometry(self.dialog_geometry)
            
        self.action_dialog.transient(self.root)
        self.action_dialog.rowconfigure(0, weight=1)  # Make dialog resizable
        self.action_dialog.columnconfigure(0, weight=1)
        
        # Create main frame with padding that fills dialog
        main_frame = ttk.Frame(self.action_dialog, padding="10")
        main_frame.grid(row=0, column=0, sticky="nsew")
        main_frame.rowconfigure(1, weight=1)  # History section
        main_frame.rowconfigure(3, weight=1)  # Action section
        main_frame.columnconfigure(0, weight=1)
        
        # Create PanedWindow to allow resizing between history and action sections
        paned = ttk.PanedWindow(main_frame, orient=tk.VERTICAL)
        paned.grid(row=1, column=0, rowspan=3, sticky="nsew")
        
        # History section
        history_frame = ttk.Frame(paned)
        history_frame.rowconfigure(1, weight=1)
        history_frame.columnconfigure(0, weight=1)
        
        history_label = ttk.Label(history_frame, text="Action History:")
        history_label.grid(row=0, column=0, sticky="w")
        
        # Add scrollbar for history text
        history_text_frame = ttk.Frame(history_frame)
        history_text_frame.grid(row=1, column=0, sticky="nsew")
        history_text_frame.rowconfigure(0, weight=1)
        history_text_frame.columnconfigure(0, weight=1)
        
        history_scroll = ttk.Scrollbar(history_text_frame)
        history_scroll.grid(row=0, column=1, sticky="ns")
        
        history_text = tk.Text(history_text_frame, wrap=tk.WORD, yscrollcommand=history_scroll.set, height=10)
        history_text.grid(row=0, column=0, sticky="nsew")
        history_scroll.config(command=history_text.yview)
        
        history_text.insert(tk.END, base_action._get_action_history(self.action_history))
        history_text.config(state=tk.DISABLED)
        
        # Action section  
        action_frame = ttk.Frame(paned)
        action_frame.rowconfigure(1, weight=1)
        action_frame.columnconfigure(0, weight=1)
        
        action_label = ttk.Label(action_frame, text="Proposed Action:")
        action_label.grid(row=0, column=0, sticky="w")
        
        # Add scrollbar for action text
        action_text_frame = ttk.Frame(action_frame)
        action_text_frame.grid(row=1, column=0, sticky="nsew")
        action_text_frame.rowconfigure(0, weight=1)
        action_text_frame.columnconfigure(0, weight=1)
        
        action_scroll = ttk.Scrollbar(action_text_frame)
        action_scroll.grid(row=0, column=1, sticky="ns")
        
        action_text = tk.Text(action_text_frame, wrap=tk.WORD, yscrollcommand=action_scroll.set, height=10)
        action_text.grid(row=0, column=0, sticky="nsew")
        action_scroll.config(command=action_text.yview)
        
        action_json = json.dumps(self.actions.model_dump(), indent=2, ensure_ascii=False)
        action_text.insert(tk.END, action_json)
        action_text.config(state=tk.DISABLED)
        
        # Add frames to paned window with equal weights
        paned.add(history_frame, weight=1)
        paned.add(action_frame, weight=1)
        
        # Button frame
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=4, column=0, sticky="ew", pady=(10,0))
        button_frame.columnconfigure((0,4), weight=1)  # Equal weight to outer columns for centering
        
        # Save geometry when window moves
        def save_geometry(event):
            self.dialog_geometry = self.action_dialog.geometry()
        self.action_dialog.bind('<Configure>', save_geometry)
        
        # Bind window close button to discard action
        self.action_dialog.protocol("WM_DELETE_WINDOW", lambda: discard_btn.invoke())

        def destroy_dialog():
            self.action_dialog.destroy()
            self.action_dialog = None

        def set_idle():
            if (m := self.mask_thread) and m.is_alive() and self.running:
                self.status_label.config(text="Status: Pending Mask Detection")
                self.call_blocking(m.join)
            self.is_updating = False
            if self.running:
                self.status_label.config(text="Status: Idle")
        
        def move_forward():
            step_callback(self.task, base64.b64encode(self.last_screenshot).decode('utf-8'), self.org_uist, self.uist, self.analyzed_ui, self.actions, self.mask_result, self.action_history, self._actions_history, self.skip_steps_by_preprocess, self.ui_change_history)
            if self.is_triggered or self.is_completed:
                result_callback(self.is_triggered, self.is_completed, False)
                if not self._close_immediately:
                    self.on_closing() # Close the window
        
        # Action buttons in center columns
        apply_btn = ttk.Button(button_frame, text="Apply", 
                             command=lambda: [destroy_dialog(), self.call_blocking(self.apply_action), self.update_display(), set_idle(), move_forward()])
        apply_btn.grid(row=0, column=1, padx=5)
        
        retry_btn = ttk.Button(button_frame, text="Retry",
                             command=lambda: [destroy_dialog(), self.trigger_action()])
        retry_btn.grid(row=0, column=2, padx=5)
        
        discard_btn = ttk.Button(button_frame, text="Discard",
                                command=lambda: [destroy_dialog(), set_idle()])
        discard_btn.grid(row=0, column=3, padx=5)

        if self.auto_apply.get():
            apply_btn.invoke()
    
    @time_consumed
    def sync_ui_screenshot(self, first_apply=True):
        """Fetch newest UI & Screenshot data"""

        # Should try to hide keyboard before getting screenshot
        base_action.hide_keyboard()

        # Should try to bring app to foreground before getting screenshot
        base_action.bring_to_foreground()

        sleep(rand(0.5, 1))

        self.assert_running()

        label = self.status_label.cget("text")

        self.status_label.config(text="Status: Getting UI & Screenshot")

        # Function to get UI in background
        def get_ui():
            try:
                nonlocal uist, org_vid_map, suc1
                uist, org_vid_map = base_ui.getui()
                self.org_vid_map = copy.deepcopy(org_vid_map)
                suc1 = True
            except Exception as e:
                logger.exception("Error getting UI")

        # Function to get screenshot in background
        def get_ss():
            try:
                nonlocal suc2
                get_screenshot()
                suc2 = True
            except Exception as e:
                logger.exception("Error getting screenshot")

        # Start both threads
        uist = org_vid_map = None
        suc1, suc2 = False, False
        ui_thread = threading.Thread(target=get_ui, daemon=True)
        ss_thread = threading.Thread(target=get_ss, daemon=True)
        ui_thread.start()
        ss_thread.start()

        # Check which thread finishes first and update status accordingly
        while ui_thread.is_alive() or ss_thread.is_alive():
            self.assert_running()
            if not ui_thread.is_alive() and ss_thread.is_alive():
                self.status_label.config(text="Status: Getting Screenshot")
            elif not ss_thread.is_alive() and ui_thread.is_alive():
                self.status_label.config(text="Status: Getting UI")
            time.sleep(0.1)
        
        if not suc1 or not suc2:
            raise Exception("Failed to get UI or screenshot")

        with open("screenshot.png", "rb") as f:
            screenshot = f.read()
        base64_screenshot = base64.b64encode(screenshot).decode('utf-8')

        # Check if ad can be closed immediately
        if first_apply and any(text in ''.join(base_ui.get_text_list(uist['elements'])) for text in ['跳过', '轻滑试试', '扭动手机', '查看详情', '立即下载', '点击下载', '赶快下载', '一键下载', '第三方应用', '点击按钮', '摇一摇', '免费领取', '跳转详情页', '反馈']):
            if (cb := base_ui.element_selector(uist['elements'], 'name', 'closeButton_id', strict=True)) is not None \
                or (cb := base_ui.element_selector(uist['elements'], 'name', 'endcard_close', strict=True)) is not None \
                or (cb := base_ui.element_selector(uist['elements'], 'name', 'bu endCardClose', strict=True)) is not None \
                or (cb := base_ui.element_selector(uist['elements'], 'name', 'CSJSlpashSkipButton', strict=True)) is not None \
                or (cb := base_ui.element_selector(uist['elements'], 'name', 'close.png', strict=False)) is not None \
                    or (cb := base_ui.element_selector(uist['elements'], 'value', '跳过', strict=False)) is not None:
                frame = base_ui.get_frame(cb)
                cb |= {'subviews': []}
                if len(cb.get('name', '')) < 20 and len(cb.get('value', '')) < 20:
                    logger.info(f"Immediately closing advertisement (selector {cb}) with frame: {frame}")
                    base_action.tap(frame['x'] + frame['width'] / 2, frame['y'] + frame['height'] / 2)
                    self.skip_steps_by_preprocess += 1
                    sleep(rand(0.5, 1))
                    return self.sync_ui_screenshot(False)
        
        # Check if app store page can be closed immediately
        if base_ui.element_selector(uist['elements'], 'name', 'AXStoreCollectionView', strict=True) is not None:
            if (cb := base_ui.element_selector(uist['elements'], 'name', 'ProductPageExtension.ProductView', strict=True)) is not None \
                    and (cb := base_ui.element_selector(cb, 'name', '完成', strict=True)) is not None:
                frame = base_ui.get_frame(cb)
                cb |= {'subviews': []}
                logger.info(f"Immediately closing app store page (selector {cb}) with frame: {frame}")
                base_action.tap(frame['x'] + frame['width'] / 2, frame['y'] + frame['height'] / 2)
                self.skip_steps_by_preprocess += 1
                sleep(rand(0.5, 1))
                return self.sync_ui_screenshot(False)
        
        # Check if rating prompt can be closed immediately
        if base_ui.element_selector(uist['elements'], 'name', '轻点星形以在App Store中评分。', strict=True) is not None:
            if (cb := base_ui.element_selector(uist['elements'], 'name', '以后', strict=True)) is not None:
                frame = base_ui.get_frame(cb)
                cb |= {'subviews': []}
                logger.info(f"Immediately closing rating prompt (selector {cb}) with frame: {frame}")
                base_action.tap(frame['x'] + frame['width'] / 2, frame['y'] + frame['height'] / 2)
                self.skip_steps_by_preprocess += 1
                sleep(rand(0.5, 1))
                return self.sync_ui_screenshot(False)
        
        # Check if sharing prompt can be closed immediately
        if (cb := base_ui.element_selector(uist['elements'], 'name', 'ActivityListView', strict=True)) is not None:
            if (cb := base_ui.element_selector(cb, 'name', 'UIActivityContentView', strict=True)) is not None:
                if (cb := base_ui.element_selector(cb, 'name', '关闭', strict=True)) is not None \
                        or (cb := base_ui.element_selector(cb, 'name', 'Close', strict=True)) is not None:
                    frame = base_ui.get_frame(cb)
                    cb |= {'subviews': []}
                    logger.info(f"Immediately closing sharing prompt (selector {cb}) with frame: {frame}")
                    base_action.tap(frame['x'] + frame['width'] / 2, frame['y'] + frame['height'] / 2)
                    self.skip_steps_by_preprocess += 1
                    sleep(rand(0.5, 1))
                    return self.sync_ui_screenshot(False)
        
        # Check if system alert can be handled immediately
        if base_ui.element_selector(uist['elements'], 'type', 'XCUIElementTypeStatusBar', strict=True) is not None \
                and (alert := base_ui.element_selector(uist['elements'], 'type', 'XCUIElementTypeAlert', strict=True)) is not None:
            # status bar is present, possibly in SpringBoard
            logger.info("System alert detected, handling immediately")
            for name in ['允许', 'Allow', '好', 'OK', '不允许', 'Don\'t Allow', '取消', 'Cancel', '关闭', 'Close']:
                if (cb := base_ui.element_selector(alert, 'name', name, strict=True)) is not None:
                    frame = base_ui.get_frame(cb)
                    base_action.tap(frame['x'] + frame['width'] / 2, frame['y'] + frame['height'] / 2)
                    self.skip_steps_by_preprocess += 1
                    sleep(rand(0.5, 1))
                    return self.sync_ui_screenshot()
        
        # Check if Game Center can be closed immediately
        if (cb := base_ui.element_selector(uist['elements'], 'name', 'GKSignInView', strict=True)) is not None:
            if (cb := base_ui.element_selector(cb, 'name', '取消', strict=True)) is not None:
                frame = base_ui.get_frame(cb)
                cb |= {'subviews': []}
                logger.info(f"Immediately closing game center (selector {cb}) with frame: {frame}")
                base_action.tap(frame['x'] + frame['width'] / 2, frame['y'] + frame['height'] / 2)
                self.skip_steps_by_preprocess += 1
                sleep(rand(0.5, 1))
                return self.sync_ui_screenshot(False)

        self.assert_running()
        self.status_label.config(text="Status: Post-processing UI")

        final_ui, vid_map = base_ui.post_process_ui(uist['elements'], base64_screenshot)

        self.assert_running()
        self.status_label.config(text=label)
        return uist, org_vid_map, base64_screenshot, final_ui, vid_map

    @time_consumed
    def fetch_ui_data(self, force_sync=True):
        """Fetch new UI & Screenshot data in background"""
        self.is_fetching_ui = True
        try:
            self.skip_steps_by_preprocess = 0
            uist, self.org_vid_map, base64_screenshot, final_ui, vid_map = self.sync_ui_screenshot()

            self.org_uist = copy.deepcopy(uist)

            # Replace with current uielements
            uist['elements'] = final_ui

            self.assert_running()
            self.status_label.config(text="Status: Analyzing UI")
            
            # Check if UI has changed
            if self.enable_ui_cache and self.cached_uist:
                
                ui_changed = not base_ui.is_ui_equal(
                    uist['elements'], 
                    self.cached_uist['elements']
                )
                
                if not ui_changed and self.cached_analyzed:
                    logger.debug("UI unchanged, using cached analysis")
                    analyzed = self.cached_analyzed
                else:
                    analyzed = base_ui.analyze_ui(final_ui, base64_screenshot)
                    # Update cache
                    self.cached_uist = uist
                    self.cached_analyzed = analyzed
            else:
                # No cache or caching disabled
                analyzed = base_ui.analyze_ui(final_ui, base64_screenshot)
                # Update cache
                self.cached_uist = uist
                self.cached_analyzed = analyzed

            # If the UI match rate is less than 0.5, re-synchronize
            if force_sync and analyzed.match_rate < 0.5:
                logger.info(f"UI match rate {analyzed.match_rate} too low, re-synchronizing")
                return self.fetch_ui_data(force_sync=False)
            
            # Update & Cache the screenshot image data
            self.last_screenshot = base64.b64decode(base64_screenshot)
            
            self.uist = uist
            self.vid_map = vid_map
            self.analyzed_ui = analyzed

            self.data_queue.put(True)
            
        except Exception as e:
            logger.exception(f"Error fetching data")
            self.data_queue.put(None)
            self.assert_running()
            self.status_label.config(text="Status: Error")
        
        self.is_fetching_ui = False
    
    @time_consumed
    def fetch_action(self):
        """Fetch new action data in background"""
        try:
            self.assert_running()
            self.status_label.config(text="Status: Analyzing Action")
            raction = self.actions.recent_repeat_action if self.actions else ''
            rcount = self.actions.recent_repeat_count if self.actions else 0
            self.actions = base_action.analyze_action(self.analyzed_ui, self.task, self.action_history, recent_repeat_action=raction, recent_repeat_count=rcount)
            self.action_queue.put(True)
        except Exception as e:
            logger.exception(f"Error fetching action")
            self.action_queue.put(None)
            self.assert_running()
            self.status_label.config(text="Status: Error")
    
    @time_consumed
    def apply_action(self):
        """Apply the action to the UI"""
        logger.debug(f"Before applying: ui_diff_count={self.ui_diff_count}, no_action_count={self.no_action_count}, last_restart={self.last_restart}, current_step={len(self.action_history)}")
        self.assert_running()
        try:
            self.status_label.config(text="Status: Checking UI")
            uist, org_vid_map, base64_screenshot, final_ui, vid_map = self.sync_ui_screenshot(False)
            if self.ui_diff_count < MAX_UI_DIFF_COUNT and not base_ui.is_ui_equal(final_ui, self.uist['elements']):
                logger.info("UI has changed, actions not being applied.")
                self.assert_running()
                self.status_label.config(text="Status: Action(s) Not Applied")
                if self.analyzed_ui.feedback_message:
                    self.action_history.append('The UI shows feedback/status/error message: \'' + self.analyzed_ui.feedback_message + '\'')
                self.ui_diff_count += 1
                self.ui_change_history.append([final_ui, base64_screenshot])
                return
            if self.ui_diff_count >= MAX_UI_DIFF_COUNT:
                logger.info("Force applying action(s) since UI has changed too much.")
            self.ui_diff_count = 0
            self.ui_change_history = []
            self.status_label.config(text="Status: Applying Action(s)")
            try:
                effective_actions = base_action.apply_actions(self.actions, self.vid_map, base_ui)
            except Exception as e:
                logger.exception(f"Error applying action")
                effective_actions = 0
            if effective_actions is True:
                # Task completed!
                self.assert_running()
                self.status_label.config(text="Status: Task Completed")
                self.is_completed = True
                return
            if effective_actions == 0:
                self.no_action_count += 1
            else:
                self.no_action_count = 0
            restart = False
            if self.no_action_count > MAX_NO_ACTION_COUNT:
                logger.info(f"Restart the app after {MAX_NO_ACTION_COUNT} times of no actions.")
                self.action_history.append('Restart the app since no actions are possible within the current UI.')
                restart = True
            if self.last_restart + MAX_STEPS_COUNT < len(self.action_history):
                logger.info(f"Restart the app after maximum steps count {MAX_STEPS_COUNT} reached.")
                self.action_history.append(f'Restart the app after maximum steps in an action sequence reached.')
                restart = True
            if restart:
                self._actions_history.append(None)
                self.no_action_count = 0
                self.last_restart = len(self.action_history)
                base_action.restart_app()
                return
            self.action_history.append(self.actions.summary.ui_summary + (' ' if not self.analyzed_ui.feedback_message or (self.analyzed_ui.ads and self.analyzed_ui.ads.is_ad_topmost) or self.analyzed_ui.feedback_message in self.actions.summary.ui_summary  else ' The UI shows feedback/status/error message: \'' + self.analyzed_ui.feedback_message + '\'. ') + self.actions.summary.action_summary)
            self._actions_history.append(self.actions)
        except Exception as e:
            logger.exception(f"Error applying action")
            self.assert_running()
            self.status_label.config(text="Status: Error")
    
    @time_consumed
    def fetch_mask(self, final_ui, base64_screenshot):
        """Fetch new mask detection data in background"""
        self.mask_result = mask_detection(final_ui, base64_screenshot)
        self.assert_running()
        if not self.mask_result:
            self.mask_label.config(text="Mask Detection: Unavailable")
            self.mask_thread = None
            return
        match self.mask_result.result:
            case "Yes":
                # Double check if the mask is actually detected
                self.mask_label.config(text="Mask Detection: Verifying")
                self.mask_result = mask_detection(final_ui, base64_screenshot)
                self.assert_running()
                match self.mask_result.result:
                    case "Yes":
                        self.mask_label.config(text="Mask Detection: Yes", foreground="green")
                        self.is_triggered = True
                    case "No":
                        self.mask_label.config(text="Mask Detection: No")
                    case result:
                        self.mask_label.config(text=f"Mask Detection: {result}")
            case "No":
                self.mask_label.config(text="Mask Detection: No")
            case result:
                self.mask_label.config(text=f"Mask Detection: {result}")
        if not self.is_fetching_ui:
            self.assert_running()
            self.root.after(100, self.update_tree) # refresh ui_desc
        self.mask_thread = None
        return

    def update_display(self):
        """Update all UI elements with new data"""
        try:
            if self._close_immediately:
                raise Exception("Window is closing")
            self.update_image()
            self.update_tree()
            self.update_action()
            self.last_refresh_time = time.time()
        except Exception as e:
            logger.exception(f"Error updating display")

    def update_action(self):
        """Update the action display"""
        step_text = 'Task: \n' + self.task + '\n\n'
        step_text += 'Action History: \n' + base_action._get_action_history(self.action_history) + '\n\n'
        if self.actions:
            step_text += 'Proposed Action: \n' + json.dumps(self.actions.model_dump(), indent=0, ensure_ascii=False) + '\n\n'
        step_text += 'Slim UI: \n' + base_action._get_ui_slim(self.analyzed_ui) + '\n\n'
            
        # Update the action text display
        self.step_desc.delete('1.0', tk.END)
        self.step_desc.insert(tk.END, step_text)

    def calculate_scale_factor(self, img_width, img_height):
        """Calculate scale factor to fit image in canvas"""
        canvas_width = max(1, self.left_frame.winfo_width() - 10)  # Account for padding
        canvas_height = max(1, self.left_frame.winfo_height() - 10)
        
        width_scale = canvas_width / max(1, img_width)
        height_scale = canvas_height / max(1, img_height + 20) # Make bottom visible
        return min(width_scale, height_scale)

    def update_image(self):
        """Update the screenshot display"""
        try:
            self.is_resize_done = True

            # Use cached image data instead of reading from disk
            if not self.last_screenshot:
                logger.error("No screenshot data available")
                return
            
            # Create image from cached data
            from io import BytesIO
            img = Image.open(BytesIO(self.last_screenshot))
            
            # Ensure valid dimensions
            if img.size[0] <= 0 or img.size[1] <= 0:
                logger.exception("Invalid image dimensions")
                return
                
            # Calculate scale factor based on actual image size
            self.scale_factor = self.calculate_scale_factor(*img.size)
            
            # Scale image
            new_size = (max(1, int(img.size[0] * self.scale_factor)),
                       max(1, int(img.size[1] * self.scale_factor)))
            
            img = img.resize(new_size, Image.Resampling.LANCZOS)
            self.photo = ImageTk.PhotoImage(img)
            
            self.canvas.delete("all")
            self.canvas.create_image(5, 5, image=self.photo, anchor=tk.NW)  # Add 5px padding
            
            # Update canvas size to match image
            self.canvas.config(width=new_size[0]+10, height=new_size[1]+10)  # Add padding
            
            # Restore highlight if there was one
            if self.current_element_id and self.vid_map:
                self.highlight_element(self.current_element_id)
            
        except Exception as e:
            logger.exception(f"Error updating image")

    def highlight_element(self, element_id):
        """Highlight an element in the screenshot"""
        if not self.vid_map or element_id not in self.vid_map:
            return
        
        # Remove existing highlight
        if self.highlight_rect:
            self.canvas.delete(self.highlight_rect)
            self.highlight_rect = None
        
        # Get element frame
        frame = base_ui.get_frame(self.vid_map[element_id])
        
        # Scale coordinates and add padding consistently
        padding = 5  # Same padding as used in create_image
        x1 = int(frame['x'] * self.scale_factor) + padding
        y1 = int(frame['y'] * self.scale_factor) + padding
        x2 = x1 + int(frame['width'] * self.scale_factor)
        y2 = y1 + int(frame['height'] * self.scale_factor)
        
        # Create new highlight rectangle
        self.highlight_rect = self.canvas.create_rectangle(
            x1, y1, x2, y2,
            outline="red",  # Use red for better visibility
            width=2,        # Make line thicker
            dash=(5, 5)     # Use dashed line for better visibility
        )
        
        self.current_element_id = element_id

    def update_tree(self):
        """Update the UI element tree"""
        try:
            self.refresh_tree_view()
        except Exception as e:
            logger.exception(f"Error updating tree")

    def update_refresh_time(self):
        """Update the refresh time label every second"""
        if self.last_refresh_time:
            elapsed = int(time.time() - self.last_refresh_time)
            self.refresh_label.config(text=f"Refreshed {elapsed} seconds ago")
        self.root.after(1000, self.update_refresh_time)

    def on_tree_select(self, event):
        """Handle tree selection"""
        selection = self.tree.selection()
        if selection and self.vid_map:
            item = self.tree.item(selection[0])
            element_id = item['values'][0]
            
            if element_id:  # Only process if element has an ID
                # Highlight the selected element
                self.highlight_element(element_id)
                
                # Find selected element in vid_map
                element_info = self.vid_map.get(element_id)
                
                # Find if it's an analyzed element
                analyzed_element = next((e for e in self.analyzed_ui.elements 
                                      if e.id == element_id), None)
                
                # Update details
                self.details_text.delete(1.0, tk.END)
                
                if element_info:
                    details = f"[{element_id}] {element_info.get('type', 'Unknown')}\n"
                    details += f"Position: ({base_ui.get_frame(element_info)['x']}, {base_ui.get_frame(element_info)['y']})\n"
                    details += f"Size: {base_ui.get_frame(element_info)['width']}x{base_ui.get_frame(element_info)['height']}\n"
                    if 'name' in element_info:
                        details += f"Name: {element_info['name']}\n"
                    details += "\n"
                    if analyzed_element:
                        details += f"\nAnalyzed as:\n"
                        details += f"Type: {analyzed_element.ui_type.value}\n"
                        details += f"Description: {analyzed_element.description}\n"
                        details += f"Confidence: {analyzed_element.clickability}\n"
                        #details += f"Click Action: {analyzed_element.click_action}\n"
                        details += f"Text: {analyzed_element.text}\n"
                        details += f"Location: {analyzed_element.location}\n"
                        details += "\n"
                    details += "\n"
                    details += json.dumps(element_info | {'subviews': []}, indent=2, ensure_ascii=False, sort_keys=True)
                    details += "\n\n"
                    details += json.dumps(self.org_vid_map.get(element_info.get('_id', element_info['id']), {}) | {'subviews': []}, indent=2, ensure_ascii=False, sort_keys=True)
                    
                    self.details_text.insert(tk.END, details)

    def on_canvas_click(self, event):
        """Handle clicks on the screenshot"""
        if not self.vid_map:
            return
        
        # Get click coordinates relative to canvas
        click_x = event.x - 5  # Adjust for padding
        click_y = event.y - 5
        
        # Convert click coordinates back to original scale
        orig_x = int(click_x / self.scale_factor)
        orig_y = int(click_y / self.scale_factor)
        
        suitable_element, depth, size = self.find_suitable_element(orig_x, orig_y)
        
        if suitable_element:
            element_id = suitable_element['id']
            logger.info(f"Clicked suitable element {element_id} at depth {depth} of size {size}")
            
            # Check if this element is analyzed
            analyzed_element = next((e for e in self.analyzed_ui.elements 
                                   if e.id == element_id), None)
            
            # Highlight the element
            self.highlight_element(element_id)
            
            # Find and select the element in tree
            def find_and_select_in_tree(items):
                for item in items:
                    values = self.tree.item(item)['values']
                    if values and values[0] == element_id:
                        self.tree.selection_set(item)
                        self.tree.see(item)
                        return True
                    if find_and_select_in_tree(self.tree.get_children(item)):
                        return True
                return False
            
            find_and_select_in_tree(self.tree.get_children())

    def on_window_resize(self, event):
        """Handle window resize events"""
        # Only update if it's the root window being resized
        if event.widget == self.root and self.is_resize_done:
            self.is_resize_done = False
            # Add delay to avoid too frequent updates
            self.root.after(100, self.update_image)

    def on_closing(self):
        """Handle window closing"""
        logger.info("Shutting down application...")

        # Disable auto refresh
        self.auto_refresh.set(False)
        self.auto_apply.set(True)

        # Stop any running threads
        if hasattr(self, 'mask_thread') and (m := self.mask_thread) and m.is_alive():
            self.call_blocking(m.join)

        # Wait for any pending updates
        start_time = time.time()
        while self.is_updating:
            if time.time() - start_time > 30:
                break
            time.sleep(0.1)
            self.root.update()
        
        # Force stopping
        self.running = False

        # Stop any running threads
        if hasattr(self, 'mask_thread') and (m := self.mask_thread) and m.is_alive():
            self.call_blocking(m.join)

        # Wait for any pending updates
        start_time = time.time()
        while self.is_updating:
            if time.time() - start_time > 30:
                break
            time.sleep(0.1)
            self.root.update()

        # Destroy all widgets properly
        for widget in self.root.winfo_children():
            widget.destroy()

        # Cancel any pending after callbacks
        for after_id in self.root.tk.eval('after info').split():
            try:
                self.root.after_cancel(after_id)
            except Exception as e:
                logger.exception(f"Error canceling after callback {after_id}")
        
        root = self.root

        # Clear all variables
        for attr in vars(self).keys():
            if not attr.startswith('__') and not callable(getattr(self, attr)):
                try:
                    setattr(self, attr, None)
                except:
                    pass
        
        root.quit()
        root.destroy()
        import gc; gc.collect()

    def refresh_tree_view(self):
        """Refresh tree view with full UI tree while preserving expanded state"""
        if not self.vid_map or not self.analyzed_ui:
            return
        
        # Store current tree state
        expanded_items = {}
        selected_items = self.tree.selection()
        
        def store_expanded_state(items):
            for item in items:
                if self.tree.item(item)['open']:
                    # Store the item's values to identify it later
                    values = self.tree.item(item)['values']
                    if values and values[0]:  # If item has an ID
                        expanded_items[values[0]] = True
                store_expanded_state(self.tree.get_children(item))
        
        store_expanded_state(self.tree.get_children())

        def get_element_label(element):
            """Get the label for an element"""
            # Check if this element is analyzed
            analyzed_element = next((e for e in self.analyzed_ui.elements 
                                    if e.id == element.get('id')), None)
            
            # Prepare display text and tags
            element_id = element.get('id', '')
            text = f"[{element_id}] {element.get('type', 'Unknown')}"
            text += " " + ("+" if element.get('ocr_text', '') else "-") +  " "
            if 'name' in element and element['name']:
                name = (element['name'] if isinstance(element['name'], str) else ' '.join(element['name'])).replace('\n', ' ').replace('\r', '').replace('\t', ' ')
                text += f"{name[:30]}"
            if analyzed_element:
                text += f" ({analyzed_element.ui_type.value})"
            
            return text
        
        # Check if UI structure has changed by comparing labels
        current_labels = set()
        def collect_labels(items):
            for item in items:
                label = self.tree.item(item)['text']
                current_labels.add(label)
                collect_labels(self.tree.get_children(item))
        
        collect_labels(self.tree.get_children())
        
        new_labels = set()
        def collect_new_labels(element):
            # Build label in same format as tree view
            new_labels.add(get_element_label(element))
            
            for subview in element.get('subviews', []):
                collect_new_labels(subview)
        
        collect_new_labels(self.uist['elements'])
        
        ui_changed = current_labels != new_labels

        logger.debug(f"UI changed: {ui_changed}")
        
        selected_ids = []

        if ui_changed:
            # Clear selection, highlight and descriptions
            self.current_element_id = None
            if self.highlight_rect:
                self.canvas.delete(self.highlight_rect)
                self.highlight_rect = None
            self.details_text.delete(1.0, tk.END)
            selected_items = []  # Don't restore selection if UI changed
            expanded_items = {}  # Don't restore expanded state if UI changed
        else:
            # Get IDs of previously selected items
            for item in selected_items:
                try:
                    values = self.tree.item(item)['values']
                    if values:
                        selected_ids.append(values[0])
                except:
                    continue
        
        # Clear and rebuild tree
        self.tree.delete(*self.tree.get_children())

        analyzed_paths = set()  # Track paths to analyzed elements
        
        def collect_analyzed_paths(element, path=[]):
            """Collect all paths to analyzed elements"""
            current_path = path + [element.get('id', '')]
            
            # Check if this element is analyzed
            if next((e for e in self.analyzed_ui.elements if e.id == element.get('id')), None):
                analyzed_paths.update(current_path)
            
            # Check children
            for subview in element.get('subviews', []):
                collect_analyzed_paths(subview, current_path)
        
        # First collect all paths to analyzed elements
        collect_analyzed_paths(self.uist['elements'])
        
        def insert_element(element, parent=""):
            # Check if this element is analyzed
            analyzed_element = next((e for e in self.analyzed_ui.elements 
                                  if e.id == element.get('id')), None)
            
            # Prepare display text and tags
            element_id = element.get('id', '')
            text = get_element_label(element)
            
            tags = ('analyzed',) if analyzed_element else ()
            
            # Determine if this item should be expanded
            should_expand = (
                element_id in expanded_items or  # Was previously expanded
                element_id in analyzed_paths     # Is in path to analyzed element
            )
            
            # Insert element with only text
            item_id = self.tree.insert(parent, "end", 
                                     text=text,
                                     values=(element_id,),  # Keep ID in values for lookup
                                     tags=tags,
                                     open=should_expand)
            
            # Insert children
            for subview in element.get('subviews', []):
                insert_element(subview, item_id)
            
            return item_id
        
        # Configure tag for highlighted items
        self.tree.tag_configure('analyzed', foreground='blue', font=('TkDefaultFont', 9, 'bold'))
        
        # Insert full tree
        insert_element(self.uist['elements'])
        
        # Restore selection if items still exist
        def find_item_by_id(items, target_id):
            """Recursively search for item with matching ID"""
            for item in items:
                values = self.tree.item(item)['values']
                if values and values[0] == target_id:
                    return item
                # Search children
                child_result = find_item_by_id(self.tree.get_children(item), target_id)
                if child_result:
                    return child_result
            return None

        # Find and select items with matching IDs
        for element_id in selected_ids:
            found_item = find_item_by_id(self.tree.get_children(), element_id)
            if found_item:
                self.tree.selection_add(found_item)
                self.tree.see(found_item)
        
        # Build the description text
        desc_text = ""
        desc_text += "GPT Analysis:\n"
        desc_text += self.analyzed_ui.description
        desc_text += "\n\nFeedback message:\n"
        desc_text += self.analyzed_ui.feedback_message
        desc_text += "\n\nIs alert topmost: " + str(self.analyzed_ui.is_alert_topmost)
        if self.analyzed_ui.ads:
            desc_text += "\nIs ad topmost: " + str(self.analyzed_ui.ads.is_ad_topmost)
            desc_text += "\nIs ad closeable: " + str(self.analyzed_ui.ads.is_ad_closeable)
            desc_text += "\nAd close button id: " + str(self.analyzed_ui.ads.ad_close_button_id)
        if self.mask_result:
            desc_text += "\n\nMask Detection: " + self.mask_result.result + ', ' + self.mask_result.reasoning
        desc_text += "\n\nUI Tree Statistics:\n"
        
        total_elements = self.count_elements(self.uist['elements'])
        analyzed_elements = len(self.analyzed_ui.elements)
        desc_text += f"Total elements: {total_elements}\n"
        desc_text += f"Match rate: {self.analyzed_ui.match_rate}\n"
        desc_text += f"Analyzed elements: {analyzed_elements}\n"
        desc_text += f"Analysis ratio: {analyzed_elements/total_elements*100:.1f}%\n\n"
        
        # Add screen info
        if 'screenscale' in self.uist:
            desc_text += f"Screen scale: {self.uist['screenscale']}x\n"
        
        # Add analyzed elements summary
        desc_text += "\nAnalyzed Elements Summary:\n"
        for element in self.analyzed_ui.elements:
            frame = base_ui.get_frame(self.vid_map[element.id])
            desc_text += (f"[{element.id}] {element.ui_type.value} at ({frame['x']}, {frame['y']}) "
                        f"size {frame['width']}x{frame['height']}\n")
        
        # Update the text widget
        self.ui_desc.delete(1.0, tk.END)
        self.ui_desc.insert(tk.END, desc_text)

    def count_elements(self, element):
        """Count total number of elements in UI tree"""
        count = 1  # Count current element
        for subview in element.get('subviews', []):
            count += self.count_elements(subview)
        return count

    def deselect_element(self):
        """Deselect current element"""
        self.tree.selection_remove(*self.tree.selection())
        if self.highlight_rect:
            self.canvas.delete(self.highlight_rect)
            self.highlight_rect = None
        self.current_element_id = None
        self.details_text.delete(1.0, tk.END)

    def show_canvas_menu(self, event):
        """Show context menu for canvas right-click"""
        # Get click coordinates relative to canvas
        click_x = event.x - 5  # Adjust for padding
        click_y = event.y - 5
        
        # Convert to original coordinates
        orig_x = int(click_x / self.scale_factor)
        orig_y = int(click_y / self.scale_factor)
        
        self.last_right_click_pos = (orig_x, orig_y)
        
        # Find suitable element at click position
        suitable_element, depth, size = self.find_suitable_element(orig_x, orig_y)
        
        # Clear and rebuild menu
        self.canvas_menu.delete(0, tk.END)
        
        # Always show position
        self.canvas_menu.add_command(
            label=f"Position: ({orig_x}, {orig_y})"
        )
        
        if suitable_element:
            # Show element info if found
            self.canvas_menu.add_separator()
            self.canvas_menu.add_command(
                label=f"Element: [{suitable_element['id']}] at depth {depth} of size {size}"
            )
        
        # Always show click and deselect options
        self.canvas_menu.add_separator()
        self.canvas_menu.add_command(
            label="Deselect",
            command=self.deselect_element
        )
        self.canvas_menu.add_command(
            label="Click Here",
            command=self.click_position
        )
        
        self.canvas_menu.tk_popup(event.x_root, event.y_root)

    def show_tree_menu(self, event):
        """Show context menu for tree view right-click"""
        # Get the item under cursor
        item = self.tree.identify('item', event.x, event.y)
        if not item:
            return
        
        # Get element info
        values = self.tree.item(item)['values']
        if not values or not values[0]:
            return
        
        element_id = values[0]
        element_info = self.vid_map.get(int(element_id))  # Convert id to int
        if not element_info:
            return
        
        # Store element for click operation
        self.last_right_click_element = element_info
        
        # Build menu
        self.element_menu.delete(0, tk.END)
        self.element_menu.add_command(
            label=f"Element: [{element_id}]"
        )
        self.element_menu.add_separator()
        self.element_menu.add_command(
            label="Deselect",
            command=self.deselect_element
        )
        self.element_menu.add_command(
            label="Click Center",
            command=self.click_element_center
        )
        
        self.element_menu.tk_popup(event.x_root, event.y_root)

    def find_suitable_element(self, x, y):
        """Find the most suitable (smallest containing) element at the given coordinates"""
        if not self.vid_map:
            return None, 0
            
        return base_ui.find_suitable_element(self.uist['elements'], x, y, 0, 0)

    def click_position(self):
        """Click the last right-clicked position using ZXTouch"""
        if self.last_right_click_pos:
            x, y = self.last_right_click_pos
            try:
                base_action.tap(x, y)
                logger.info(f"Clicked position ({x}, {y})")
            except Exception as e:
                logger.exception(f"Failed to click position")

    def click_element_center(self):
        """Click the center of the last right-clicked element using ZXTouch"""
        if self.last_right_click_element:
            frame = base_ui.get_frame(self.last_right_click_element)
            center_x = frame['x'] + frame['width'] // 2
            center_y = frame['y'] + frame['height'] // 2
            try:
                base_action.tap(center_x, center_y)
                logger.info(f"Clicked element center at ({center_x}, {center_y})")
            except Exception as e:
                logger.exception(f"Failed to click element")

