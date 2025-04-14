STATUS_BAR_PIXELS = 80

import base64
import tkinter as tk
from tkinter import ttk
import os
import json

### Logging configuration
import logging
logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s] %(levelname)s [%(name)s:%(lineno)s] %(message)s',
    handlers=[
        logging.FileHandler('benchmarking.log', mode='a', encoding='utf-8'),  # Logs to file
        logging.StreamHandler()  # Logs to console
    ]
)
logger = logging.getLogger(__name__)

from gpt_cls import DetectMaskResult, UIView, UserAction

from ui_cls import AppiumUI, BaseUI

from action_cls import BaseAction

from utils import suppress_status_bar

app, root = None, None

def render_ui(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)

    task = data.get('task', '')
    base64_screenshot = data['base64_screenshot']
    org_uist = data['org_uist']
    uist = data['uist']
    analyzed_ui = data['analyzed_ui']
    actions = data['actions']
    mask_result = data['mask_result']
    action_history = data['action_history']

    app.task = task

    app.analyzed_ui = UIView.model_validate(analyzed_ui, strict=False)

    app.org_uist = org_uist
    app.org_vid_map = BaseUI.get_vid_map(org_uist['elements'])
    
    app.uist = uist
    app.vid_map = AppiumUI.get_vid_map(uist['elements'])
    
    app.last_screenshot = base64.b64decode(base64_screenshot)

    app.actions = UserAction.model_validate(actions, strict=False)
    if mask_result:
        app.mask_result = DetectMaskResult.model_validate(mask_result, strict=False)
    else:
        app.mask_result = None
    app.action_history = action_history

    if app.mask_result:
        match app.mask_result.result:
            case "Yes":
                app.mask_label.config(text="Mask Detection: Yes", foreground="green")
            case "No":
                app.mask_label.config(text="Mask Detection: No", foreground="black")
            case result:
                app.mask_label.config(text=f"Mask Detection: {result}", foreground="black")

    app.update_display()

class BenchmarkViewer:
    def __init__(self, root):
        self.root = root
        self.root.title("Benchmark Files")
        
        # Set initial window size
        self.root.geometry("600x400")
        
        # Make window resizable
        self.root.resizable(True, True)
        
        # Create main frame that expands with window
        main_frame = ttk.Frame(root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create and configure listbox with scrollbar
        self.listbox_frame = ttk.Frame(main_frame)
        self.listbox_frame.pack(fill=tk.BOTH, expand=True)
        
        self.listbox = tk.Listbox(self.listbox_frame)
        scrollbar = ttk.Scrollbar(self.listbox_frame, orient="vertical", command=self.listbox.yview)
        self.listbox.configure(yscrollcommand=scrollbar.set)
        
        self.listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Selection label (centered)
        self.selection_label = ttk.Label(main_frame, text="Current selection: None", anchor="center")
        self.selection_label.pack(fill=tk.X)
        
        # Button frame for Next and Previous buttons (centered)
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        # Center the buttons by adding a space-filling frame on each side
        ttk.Frame(button_frame).pack(side=tk.LEFT, expand=True)
        
        # Previous button
        self.prev_button = ttk.Button(button_frame, text="Previous", command=self.prev_item)
        self.prev_button.pack(side=tk.LEFT, padx=5)
        
        # Next button
        self.next_button = ttk.Button(button_frame, text="Next", command=self.next_item)
        self.next_button.pack(side=tk.LEFT, padx=5)
        
        # Add another space-filling frame for centering
        ttk.Frame(button_frame).pack(side=tk.LEFT, expand=True)
        
        # Bind selection event
        self.listbox.bind('<<ListboxSelect>>', self.on_select)
        
        # Load files
        self.load_files()
        
    def load_files(self):
        self.files = []
        folders = ['.\\cached\\results\\']
        
        for folder in folders:
            if os.path.exists(folder):
                for root, _, files in os.walk(folder):
                    for file in sorted(files):
                        filename = file.replace('\\', '/').split('/')[-1]
                        if filename.startswith('step_') and filename.endswith('.json'):
                            full_path = os.path.join(root, file)
                            self.files.append(full_path)
        import natsort
        self.files = natsort.natsorted(self.files)
        print(len(self.files))
        for i, file in enumerate(self.files):
            dirs = file.replace('\\', '/').split('/')[-2]
            next_dir = self.files[i + 1].replace('\\', '/').split('/')[-2] if i < len(self.files) - 1 else None
            is_same_dir = (dirs == next_dir)
            self.listbox.insert(tk.END, file)
            if not is_same_dir:
                self.listbox.itemconfig(tk.END, {'fg': 'blue'})
                if os.path.exists(res := os.path.join(os.path.dirname(file), 'res.json')):
                    with open(res, 'r', encoding='utf-8') as f:
                        res = json.load(f)
                    if res.get('mask_triggered', ''):
                        self.listbox.itemconfig(tk.END, {'fg': 'red'})
                    elif res.get('task_completed', ''):
                        self.listbox.itemconfig(tk.END, {'fg': 'green'})
    

    def on_select(self, event):
        if self.listbox.curselection():
            selection = self.listbox.get(self.listbox.curselection())
            self.selection_label.config(text="Current selection: " + selection.split('\\', maxsplit=3)[3])
            render_ui(selection)
    
    def next_item(self):
        if not self.listbox.curselection():
            if self.listbox.size() > 0:
                self.listbox.selection_set(0)
        else:
            current = self.listbox.curselection()[0]
            if current < self.listbox.size() - 1:
                self.listbox.selection_clear(0, tk.END)
                self.listbox.selection_set(current + 1)
                self.listbox.see(current + 1)
        self.listbox.event_generate('<<ListboxSelect>>')
    
    def prev_item(self):
        if not self.listbox.curselection():
            if self.listbox.size() > 0:
                self.listbox.selection_set(self.listbox.size() - 1)
        else:
            current = self.listbox.curselection()[0]
            if current > 0:
                self.listbox.selection_clear(0, tk.END)
                self.listbox.selection_set(current - 1)
                self.listbox.see(current - 1)
        self.listbox.event_generate('<<ListboxSelect>>')


def app_window():
    from app_window import App
    global app, root
    root, app = App.create_window(((lambda: None, lambda: None), lambda: None, lambda: None, AppiumUI, BaseAction))
    app.running = False
    app.is_updating = True

    # Bring window to front
    root.lift()
    root.attributes('-topmost', True)
    root.attributes('-topmost', False)

    # Start main loop
    #root.mainloop()

if __name__ == '__main__':
    app_window()
    root1 = tk.Toplevel()
    app1 = BenchmarkViewer(root1)
    root.mainloop()
