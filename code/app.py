### Configurations
STATUS_BAR_PIXELS = 80
DEVICE_VERSION = '14.4.1'
DEVICE_UDID = 'YOUR_DEVICE_UUID'


REMOTE_IP = '127.0.0.1'
#REMOTE_IP = '192.168.3.129'

APP_IDENT = TASK = ''

with open('BATCH_TASKS.txt', 'r', encoding='utf-8') as f:
    BATCH_TASKS = [s.strip() for s in f.read().rpartition('*/')[2].partition('/*')[0].split('\n') if s.strip()]

try:
    with open('BATCH_TASKS.fin.txt', 'r', encoding='utf-8') as f:
        BATCH_TASKS_FIN = [s.strip() for s in f.read().rpartition('*/')[2].partition('/*')[0].split('\n') if s.strip()]
except:
    BATCH_TASKS_FIN = []

BATCH_TASKS = list(filter(lambda x: x not in BATCH_TASKS_FIN, BATCH_TASKS))

DEFAULT_TASK = "Get app into the first main page to finish the task."

ROUND_BASE_TIMEOUT = 600   # 10 minutes
ROUND_DEFAULT_TIMEOUT = 100
ROUND_COUNT = 2    # try two rounds
APP_COUNT = 1   # attempts for an app

UNINST_FIRST = UNINST_THEN = True

CACHE_DIR = './cached/'

import threading
import time
from utils import *

### Logging configuration
import logging
logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s] %(levelname)s [%(name)s:%(lineno)s] %(message)s',
    handlers=[
        logging.FileHandler('app.log', mode='a', encoding='utf-8'),  # Logs to file
        logging.StreamHandler()  # Logs to console
    ]
)
logger = logging.getLogger(__name__)

### Initialize the Frida script
FRSCRIPT = lambda: '''
    function appinfo() {
        function dictFromNSDictionary(nsDict) {
            var jsDict = {};
            var keys = nsDict.allKeys();
            var count = keys.count();
            for (var i = 0; i < count; i++) {
                var key = keys.objectAtIndex_(i);
                var value = nsDict.objectForKey_(key);
                jsDict[key.toString()] = value.toString();
            }

            return jsDict;
        }

        function arrayFromNSArray(nsArray) {
            var jsArray = [];
            var count = nsArray.count();
            for (var i = 0; i < count; i++) {
                jsArray[i] = nsArray.objectAtIndex_(i).toString();
            }
            return jsArray;
        }

        function infoDictionary() {
            if (ObjC.available && "NSBundle" in ObjC.classes) {
                var info = ObjC.classes.NSBundle.mainBundle().infoDictionary();
                return dictFromNSDictionary(info);
            }
            return null;
        }

        function infoLookup(key) {
            if (ObjC.available && "NSBundle" in ObjC.classes) {
                var info = ObjC.classes.NSBundle.mainBundle().infoDictionary();
                var value = info.objectForKey_(key);
                if (value === null) {
                    return value;
                } else if (value.class().toString() === "__NSCFArray") {
                    return arrayFromNSArray(value);
                } else if (value.class().toString() === "__NSCFDictionary") {
                    return dictFromNSDictionary(value);
                } else {
                    return value.toString();
                }
            }
            return null;
        }

        var output = {};
        output["Name"] = infoLookup("CFBundleName");
        output["Bundle ID"] = ObjC.classes.NSBundle.mainBundle().bundleIdentifier().toString();
        output["Version"] = infoLookup("CFBundleVersion");
        output["Bundle"] = ObjC.classes.NSBundle.mainBundle().bundlePath().toString();
        output["Data"] = ObjC.classes.NSProcessInfo.processInfo().environment().objectForKey_("HOME").toString();
        output["Binary"] = ObjC.classes.NSBundle.mainBundle().executablePath().toString();
        return output;
    }

    // Function to get the screen scale
    function getScreenScale() {
        var UIScreen = ObjC.classes.UIScreen;
        return UIScreen.mainScreen().scale();
    }

    function getui() {
        function getCGRect(frame) {
            return {
                x: frame[0][0],
                y: frame[0][1],
                width: frame[1][0],
                height: frame[1][1]
            };
        }

        // Define the function to recursively get view information
        function getViewInfo(view, parentAbsoluteX, parentAbsoluteY) {
            var viewInfo = {};
            viewInfo['class'] = view.$className; // Class name of the view
            viewInfo['type'] = view.$className;  // Compatibility with Appium
            viewInfo['description'] = view.toString(); // Description of the view
            var mysubviews = [];

            // Initialize absolute positions
            var absoluteX = parentAbsoluteX;
            var absoluteY = parentAbsoluteY;

            // Get the frame of the view
            try {
                var frame = view.frame();
                var frameDict = getCGRect(frame);
                viewInfo['frame'] = frameDict;

                // Compute absolute positions
                absoluteX = parentAbsoluteX + frameDict.x;
                absoluteY = parentAbsoluteY + frameDict.y;

                viewInfo['absolute_frame'] = {
                    x: absoluteX,
                    y: absoluteY,
                    width: frameDict.width,
                    height: frameDict.height
                };
            } catch (e) {
                // Do not set frame if it cannot be retrieved
            }

            // Get the base class
            try {
                viewInfo['baseClass'] = view.$superClassName;
            } catch (e) {
                // Do not set baseClass if it cannot be retrieved
            }

            // Get additional properties
            try {
                viewInfo['alpha'] = view.alpha();
            } catch (e) {
                // Do not set alpha if it cannot be retrieved
            }

            try {
                viewInfo['userInteractionEnabled'] = view.isUserInteractionEnabled();
            } catch (e) {
                // Do not set userInteractionEnabled if it cannot be retrieved
            }

            try {
                viewInfo['hidden'] = view.isHidden();
            } catch (e) {
                // Do not set hidden if it cannot be retrieved
            }

            try {
                viewInfo['opaque'] = view.isOpaque();
            } catch (e) {
                // Do not set opaque if it cannot be retrieved
            }

            // Get 'text' property if available
            try {
                var text = view.text();
                if (text !== null) {
                    viewInfo['text'] = text.toString();
                    viewInfo['name'] = text.toString();
                }
            } catch (e) {
                // Do not set text if it cannot be retrieved
            }

            // Get 'value' property if available
            try {
                var value = view.value();
                if (value !== null) {
                    viewInfo['value'] = value.toString();
                }
            } catch (e) {
                // Do not set value if it cannot be retrieved
            }

            // Recursively get information for subviews
            var subviews = view.subviews();
            var count = subviews.count();
            for (var i = 0; i < count; i++) {
                var subview = subviews.objectAtIndex_(i);
                var subviewInfo = getViewInfo(subview, absoluteX, absoluteY);
                mysubviews.push(subviewInfo);
            }

            viewInfo['subviews'] = mysubviews;
            return viewInfo;
        }

        var UIApplication = ObjC.classes.UIApplication;
        var keyWindow = UIApplication.sharedApplication().keyWindow();
        var rootView = keyWindow.rootViewController().view();

        // Get screen scale to adjust positions later if needed
        var screenScale = getScreenScale();

        var elementsInfo = getViewInfo(rootView, 0, 0);

        // Include screen scale in the returned data
        var result = {
            'elements': elementsInfo,
            'screenscale': screenScale
        };

        return result;

    }

    var NSAutoreleasePool = ObjC.classes.NSAutoreleasePool;

    // Get a reference to the _UICreateScreenUIImage function
    var _UICreateScreenUIImage = new NativeFunction(
        Module.findExportByName(null, '_UICreateScreenUIImage'),
        'pointer',
        []
    );

    // Convert the UIImage to PNG data
    var UIImagePNGRepresentation = new NativeFunction(
        Module.findExportByName('UIKit', 'UIImagePNGRepresentation'),
        'pointer',
        ['pointer']
    );

    function takescr(path) {
        var pool = NSAutoreleasePool.alloc().init();

        try {
            // Call the function to get the screenshot as a UIImage
            var screenImagePtr = _UICreateScreenUIImage();
            var screenImage = new ObjC.Object(screenImagePtr);

            var pngDataPtr = UIImagePNGRepresentation(screenImagePtr);
            var pngData = new ObjC.Object(pngDataPtr);

            // Define the file path where the screenshot will be saved
            var filePath = ObjC.classes.NSString.stringWithString_(path);

            // Write the PNG data to the file
            var success = pngData.writeToFile_atomically_(filePath, true);

            //screenImage.release(); // this will make SB crash
            //pngData.release();

            pool.release();

            if (success) {
                return {"code": 1, "data": "Screenshot saved to " + path.toString()};
            } else {
                return {"code": 0, "data": "Failed to save the screenshot!"};
            }
        } catch (error) {
            pool.release();
            return {"code": 0, "data": "Error: " + error.stack.toString()};
        }
    }

    function hidekeyboard() {
        var UIWindow = ObjC.classes.UIWindow;
        ObjC.schedule(ObjC.mainQueue, function () {
            if (UIWindow) {
                var windows = UIWindow.keyWindow();
                if (windows) {
                    windows.endEditing_(true);
                }
            }
        });
    }

    var SpringBoard = ObjC.classes.SBApplicationController;
    if (SpringBoard) {
        var appController = SpringBoard.sharedInstance();

        var SBSLaunchApplicationWithIdentifier = new NativeFunction(
            Module.findExportByName(null, 'SBSLaunchApplicationWithIdentifier'),
            'int', // Return type: integer (error code)
            ['pointer', 'bool'] // Argument types: CFStringRef (pointer) and Boolean
        );
    }

    function activeapp(bundleId) {
        var pool = NSAutoreleasePool.alloc().init();
        // Get the application instance using the bundle ID
        var app = appController.applicationWithBundleIdentifier_(bundleId);
        if (app) {
            var bundleIdPtr = ObjC.classes.NSString.stringWithString_(bundleId);
            var success = SBSLaunchApplicationWithIdentifier(bundleIdPtr, 0);
            pool.release();
            return {"code": 1, "data": "App activated: " + bundleId};
        } else {
            pool.release();
            return {"code": 0, "data": "App not found: " + bundleId};
        }
    }

    rpc.exports = {
        getui: getui,
        takescr: takescr,
        appinfo: appinfo,
        getscale: getScreenScale,
        hidekeyboard: hidekeyboard,
        activeapp: activeapp,
    }
'''

### Initialize the SSH connection
from ssh_cls import iOSSHClient
sc = iOSSHClient(hostname=REMOTE_IP, username="root", password="alpine", port=2200)

sc.connect()
output = sc.send_command("whoami")
assert output.strip() == 'root', f"Expected whoami: 'root', got '{output.strip()}'"

output = sc.send_command('which frida-server')
assert 'frida-server' in output, f"No 'frida-server' in device, or add it to PATH. (got '{output}')"
sc.send_command('frida-server -l 0.0.0.0:5000 1>/dev/null 2>&1 &')

### Initialize the Frida connection
from frida_cls import iOSFridaClient
fc = iOSFridaClient(hostname=REMOTE_IP, port=5000)
fc.connect()

### Initialize ZXTouch connection
from zxt_cls import ZXTouchClient
zc = ZXTouchClient(REMOTE_IP)
zc.connect()

ssize = zc.get_screen_size()
assert ssize[0], "Failed to get screen size."
SCR_WIDTH, SCR_HEIGHT = int(float(ssize[1]['width'])), int(float(ssize[1]['height']))
logger.info(f"Screen size: {SCR_WIDTH}x{SCR_HEIGHT}")

### Unlock the device
#sc.send_command('activator send libactivator.system.homebutton')
#sleep(2) # Wait some time

### Configure Appium
from appium_cls import iOSAppiumClient
desired_caps = {
    'platformName': 'iOS',
    'deviceName': 'iPhone',
    'platformVersion': DEVICE_VERSION,
    'automationName': 'XCUITest',
    'udid': DEVICE_UDID,
    'webDriverAgentUrl': f'http://{REMOTE_IP}:8100',
    #'usePreinstalledWDA': True,
    #'updatedWDABundleId': 'com.1xample.WebDriverAgentRunner',
    'noReset': True,
    'fullReset': False,
    'webviewConnectTimeout': 20000,
    'newCommandTimeout': 6000,
    'autoAcceptAlerts': False,
}
appium = iOSAppiumClient('http://127.0.0.1:4723')
print(appium.init_connection(desired_caps))
#print(appium.start_session({'app': APP_IDENT} | desired_caps))
print(appium.start_session(APP_IDENT))

fc_sb = fc.clone(); fc_sb.connect(); fc_sb.attach_to_process('SpringBoard')
gbscript_sb = fc_sb.execute_script(FRSCRIPT())
sc1 = sc.clone(); sc1.connect()

from tidevice3.api import list_devices, connect_service_provider, screenshot_png, app_install
service = connect_service_provider(DEVICE_UDID)

def app_uninstall(bundle_id: str):
    from pymobiledevice3.services.installation_proxy import InstallationProxyService
    InstallationProxyService(lockdown=service).uninstall(bundle_id)

@time_consumed
def get_screenshot():
    try:
        #run_process(['tidevice', 'screenshot', 'screenshot.png'])
        screenshot = screenshot_png(service)
        logger.debug("Screenshot saved.")

        screenshot = suppress_status_bar(screenshot, STATUS_BAR_PIXELS)
        with open("screenshot.png", "wb") as f:
            f.write(screenshot)
        return
    except Exception as e:
        logger.exception(f"Error getting screenshot: {e}")
        raise e

def set_date_location():
    from datetime import datetime
    today = datetime.today().strftime('%Y-%m-%d')
    sc.send_command(f"date -s '{today} 00:30:00 CST'")

def restore_date_location():
    from datetime import datetime
    now = datetime.today().strftime('%Y-%m-%d %H:%M:%S')
    sc.send_command(f"date -s '{now} CST'")

@time_consumed
def test_app(uninstall_first: bool = True, uninstall_then: bool = True):
    time_start = int(time.time())
    mkdir(f'{CACHE_DIR}/results/')
    SAVE_STATE = f'{CACHE_DIR}/results/{time_start}_{APP_IDENT}.json'

    app_state = {}
    app_metadata = app_state['metadata'] = {}

    ### Get appid and appinfo
    mkdir(CACHE_DIR)
    from iosapp_cls import query_appid_by_ident, query_appinfo, query_ipa, query_appcomment
    result = query_ipa(APP_IDENT, f'{CACHE_DIR}/')
    if result:
        _, ipappid, ipaversion, ipath = result
    else:
        ipappid, ipaversion, ipath = None, None, None
    APPID = query_appid_by_ident(APP_IDENT, f'{CACHE_DIR}/appid_cache.json', ipappid)
    logger.info(f"Found app: {APP_IDENT} with appid {APPID}")

    app_metadata.update({
        'ident': APP_IDENT,
        'appid': APPID,
        'name': None,
        'descr': None,
        'category': None,
        'comments': None,
        'actual_trigger_method': None,
        'actual_trigger_type': None,
    })

    if APPID:
        for _ in range(2):
            try:
                appstore_info = query_appinfo(APPID, f'{CACHE_DIR}/{APP_IDENT}.json')
                app_metadata['name'], app_metadata['descr'], app_metadata['category'] = appstore_info['name'], appstore_info['description'], appstore_info['category']
                logger.info(f"Found appstore info: {appstore_info}")
                break
            except Exception:
                logger.exception(f"Error fetching app info for {APPID}")
                sleep(3)
        else:
            APPID = None
    if not APPID:
        logger.warning(f"Could not load appinfo from cache, disabling mask detection.")
    
    app_attempts = {}
    app_state['attempts'] = [app_attempts]
    app_attempts['time_consumed'] = None

    app_module_task_inference = {}
    app_attempts['module_task_inference'] = app_module_task_inference
    app_module_task_inference.update({
        '_response': None,
        'is_mask_probability': None,
        'is_mask_valid': None,
        'tasks_info': None,
        'failed_inference_reason': None,
        'is_trigger_inferrable_from_comments': None,
        'is_first_task_correct': None,
        'time_consumed': None,
        'token_count': None,
    })

    mkdir(f'{CACHE_DIR}/tasks/')
    SAVE_TASK = f'{CACHE_DIR}/tasks/{time_start}_{APP_IDENT}_tasks.json'
    rtask = {}

    global TASK
    if TASK is None:
        start_time0 = time.time()
        clear_time_consumed()
        clear_token_record()
        # Infer task from app comments
        for _ in range(2):
            try:
                app_comments = query_appcomment(APPID, f'{CACHE_DIR}/{APP_IDENT}.comments.json')
                app_metadata['comments'] = app_comments
                break
            except Exception:
                logger.exception(f"Error fetching app comments")
                sleep(3)
        else:
            logger.warning(f"Failed to fetch app comments for {APP_IDENT} after 3 attempts")
            app_comments = []
        logger.info(f"Found {len(app_comments)} comments for {APP_IDENT}")
        if len(app_comments) == 0 or not APPID:
            logger.warning(f"No comments found for {APP_IDENT}, using default task.")
            TASK = [(DEFAULT_TASK, ROUND_DEFAULT_TIMEOUT)]
        else:
            from gpt_cls import GPTClient
            gpt = GPTClient()
            tr = gpt.predict_task(app_comments, appstore_info)
            rtask['tr'] = app_module_task_inference['_response'] = tr.model_dump(mode='json')
            app_module_task_inference['is_mask_probability'] = tr.is_mask_package_probability
            app_module_task_inference['is_mask_valid'] = tr.is_mask_package_valid
            logger.debug(f"Inferred mask app probability: {tr.is_mask_package} / {tr.is_mask_package_probability}")
            if len(tr.inferred_triggers) == 0 or len(gpt._render_trigger_response(trigger_field=tr.inferred_triggers[0])) == 0:
                logger.warning(f"No triggers found for {APP_IDENT}, using default task.")
                TASK = [(DEFAULT_TASK, ROUND_DEFAULT_TIMEOUT)]
            else:
                TASK = [(gpt._render_trigger_response(trigger_field=t), max(ROUND_DEFAULT_TIMEOUT, int(ROUND_BASE_TIMEOUT * tr.is_mask_package_probability * t.confidence))) for t in sorted(tr.inferred_triggers, key=lambda x: x.confidence, reverse=True)]
                app_module_task_inference['tasks_info'] = [{'task': gpt._render_trigger_response(trigger_field=t), 'confidence': t.confidence, 'timeout': max(ROUND_DEFAULT_TIMEOUT, int(ROUND_BASE_TIMEOUT * tr.is_mask_package_probability * t.confidence)), 'is_task_correct': None} for t in sorted(tr.inferred_triggers, key=lambda x: x.confidence, reverse=True)]
        app_module_task_inference['time_consumed'] = time.time() - start_time0
        app_module_task_inference['token_count'] = get_token_consumed('predict_task')
    
    rtask['task'] = TASK
    with open(SAVE_TASK, 'w', encoding='utf-8') as f:
        import json
        json.dump(rtask, f, ensure_ascii=False)

    logger.info(f"Task for {APP_IDENT}: {TASK}")

    if ipath and uninstall_first and UNINST_FIRST:
        logger.info(f"Uninstall app {APP_IDENT} first from device")
        #run_process(['t3', 'app', 'uninstall', APP_IDENT])
        try:
            app_uninstall(APP_IDENT)
        except:
            raise RuntimeError('Lockdown service has been drooped; Unrecoverable.')

    ### Dump app list
    try:
        apps = fc.list_applications()
    except:
        raise RuntimeError('Frida connection has been dropped; Unrecoverable.')
    with open('apps.json', 'w', encoding='utf-8') as f:
        import json
        json.dump(apps, f, indent=4, ensure_ascii=False)

    ### Find the app
    APP_NAME = fc.get_name_by_identifier(APP_IDENT)
    if not APP_NAME:
        logger.warning(f"App bundle identifier '{APP_IDENT}' not found in device.")
        if not ipath:
            raise Exception("App not found in device, and no ipa file found.")
        logger.info(f"Install app from ipa file: " + ipath.rpartition('/')[2].rpartition('\\')[2])
        #run_process(['t3', 'install', ipath])
        app_install(service, ipath)
        for i in range(3):
            sleep(i)
            APP_NAME = fc.get_name_by_identifier(APP_IDENT)
            if APP_NAME:
                break
        if not APP_NAME:
            sleep(60) # possibly stuck
            assert APP_NAME, f"App bundle identifier '{APP_IDENT}' not found in device."
    logger.info(f"Found app: {APP_NAME}")

    app_attempts['is_app_crash'] = False
    app_attempts['app_running_state'] = None
    app_attempts['rounds'] = []

    clear_time_consumed()
    clear_token_record()

    close_window = None
    round_count = 0
    result_trigger = None
    @time_consumed
    def round():
        time_start = int(time.time())
        app_rounds = {
            'preprocess_time': None,
            'steps': [],
            'mask_result': None,
            'can_manual_trigger': None,
            'is_mask_result_correct': None,
        }
        app_attempts['rounds'].append(app_rounds)
        nonlocal round_count, result_trigger
        round_count += 1
        result_trigger = False
        logger.info(f"Round {round_count} for {APP_IDENT} of {APP_NAME} started at {time_start}")
        SAVE_DIR = f'{CACHE_DIR}/results/{time_start}_{APP_IDENT}_{round_count}/'
        mkdir(SAVE_DIR)
        step_count = 0

        getcps = lambda: next(filter(lambda p: p['name'] == APP_NAME, fc.list_processes()), None)
        if (cps := getcps()) is not None:
            logger.warning(f"App '{APP_NAME}' is already running with PID {cps['pid']}. Killing...")
            fc.kill_process(cps['pid'])
        wait_until(getcps, lambda p: p is None)

        ### Start the app
        #sc.send_command(f"open {APP_IDENT}")
        #cps = wait_until(getcps, lambda p: p is not None)
        #fc.attach_to_process(cps['pid'])
        pid = fc.spawn_and_attach(APP_IDENT)
        logger.info(f"Attached to app '{APP_NAME}' with PID {pid}")

        gbscript = fc.execute_script(FRSCRIPT())

        ### Get the app info
        appinfo = gbscript.exports_sync.appinfo()
        logger.info(f"App info: {appinfo}")
        with open('appinfo.json', 'w', encoding='utf-8') as f:
            import json
            json.dump(appinfo, f, indent=4, ensure_ascii=False)

        ### Get the UI elements & screenshot
        from ui_cls import AppiumUI
        appium_ui = AppiumUI.create_ui((gbscript, appium))
        #from ui_cls import FridaUI
        #frida_ui = FridaUI.create_ui((gbscript, ))

        # Auto accept in random tests
        appium.auto_accept_alerts(True)

        # All done, resume the app
        fc.resume_process(pid)

        # Some time for the app to start
        sleep(1)

        # Auto accept in random tests
        appium.auto_accept_alerts(True)

        # Wrapper for app replacement
        restart_app_wrapper = None
        restart_app = lambda: restart_app_wrapper()

        from action_cls import iOSAction
        action = iOSAction.create_action((restart_app, zc, appium_ui, (lambda: gbscript_sb.exports_sync.activeapp(APP_IDENT)), gbscript))

        def restart_app_func():
            # bring to foreground and kill
            # gbscript_sb.exports_sync.activeapp(APP_IDENT)
            nonlocal gbscript
            # try:
            #     gbscript.unload()
            # except:
            #     ...
            # reduce the possibility of crashing...
            gbscript_sb.exports_sync.activeapp(APP_IDENT)
            try:
                fc.detach_and_kill()
            except:
                ...
            logger.info("Restarting app...")
            sleep(1)
            pid = fc.spawn_and_attach(APP_IDENT)
            gbscript = fc.execute_script(FRSCRIPT())
            sleep(1)
            fc.resume_process(pid)
            appium_ui.replace_ui((gbscript, appium))
            action.replace_action((restart_app, zc, appium_ui, (lambda: gbscript_sb.exports_sync.activeapp(APP_IDENT)), gbscript))
            logger.info("App restarted.")
            return
        restart_app_wrapper = restart_app_func

        # Restart (for first time)
        restart_app()

        # Auto accept in random tests
        appium.auto_accept_alerts(True)

        appium.get_page_source() # Test if app has crashed
        gbscript_sb.exports_sync.activeapp(APP_IDENT)
        gbscript.exports_sync.hidekeyboard() # Test if app has crashed

        # Random tests to trigger
        logger.info("Random tests to trigger")
        def random_click(x_scale, y_scale, count=10, interval=0):
            for _ in range(count):
                zc.tap(SCR_WIDTH * x_scale, SCR_HEIGHT * y_scale, duration=50)
                sleep(interval)
        for y in range(700, 550, -15):
            random_click(1/2, y / 1000, 2)
            random_click(0.663, y / 1000, 2)
        random_click(1/4, 1/4)
        random_click(3/4, 1/4)
        random_click(1/4, 3/4)
        random_click(3/4, 3/4)
        random_click(1/2, 1/2)
        for y in range(700, 550, -15):
            random_click(1/2, y / 1000, 2)
            random_click(0.663, y / 1000, 2)

        # Restart (after random tests)
        sleep(1)
        restart_app()

        # Disable auto accept again
        appium.auto_accept_alerts(False)

        sleep(3)
        appium.get_page_source() # Test if app has crashed
        gbscript_sb.exports_sync.activeapp(APP_IDENT)
        gbscript.exports_sync.hidekeyboard() # Test if app has crashed

        def mask_detection(uielements: dict, base64_screenshot: str) -> None|object:
            if not APPID:
                return None
            from gpt_cls import GPTClient
            gpt = GPTClient()
            from ui_cls import BaseUI
            result = gpt.detect_mask(base64_screenshot, BaseUI.get_text_list(uielements), appstore_info)
            return result

        start_time = step_time = time.time()

        def result_callback(mask_triggered: bool, task_completed: bool, is_restart: bool):
            logger.info(f"Task completed: {task_completed}, mask: {mask_triggered}, restart: {is_restart}")
            with open(f'{SAVE_DIR}/res.json', 'w', encoding='utf-8') as f:
                import json
                json.dump({
                    'time': time.time() - start_time,
                    'mask_triggered': mask_triggered,
                    'task_completed': task_completed,
                    'is_restart': is_restart,
                }, f, indent=0)
            if mask_triggered:
                app_rounds['mask_result'] = mask_triggered
            elif task_completed:
                app_rounds['mask_result'] = False
            if is_restart:
                app_attempts['is_app_crash'] = True
            nonlocal result_trigger
            result_trigger = mask_triggered

        def step_callback(task: str, base64_screenshot: str, org_uist: dict, uist: dict, analyzed_ui: object, actions: object, mask_result: object, action_history: list[str], _actions_history: list[object], skip_steps_by_preprocess: int, ui_change_history: list[object]):
            nonlocal step_count, step_time
            step_count += 1
            logger.info(f"Step {step_count} for {APP_IDENT} of {APP_NAME} at {time.time()}")
            with open(f'{SAVE_DIR}/step_{step_count}.json', 'w', encoding='utf-8') as f:
                import json
                json.dump({
                    'time': time.time() - step_time,
                    'task': task,
                    'base64_screenshot': base64_screenshot,
                    'org_uist': org_uist,
                    'uist': uist,
                    'analyzed_ui': analyzed_ui.model_dump(mode='json'),
                    'actions': actions.model_dump(mode='json'),
                    'mask_result': mask_result.model_dump(mode='json') if mask_result else None,
                    'action_history': action_history,
                }, f, indent=0)
            app_rounds['steps'].append({
                'time_consumed': time.time() - step_time,
                'module_ui_comprehension': {
                    'old_view_hierarchy': org_uist,
                    'view_hierarchy': uist,
                    'screenshot': base64_screenshot,
                    '_response': analyzed_ui.model_dump(mode='json'),
                    'is_vh_complete': None,
                    'valid_ocr_text': None,
                    'valid_icon_label': None,
                    'failed_comp_reason': None,
                    'is_page_topmost_ads': None,
                    'is_page_topmost_popup': None,
                    'skip_steps_by_preprocess': skip_steps_by_preprocess,
                    'time_consumed': get_time_consumed('App.fetch_ui_data'),
                    'token_count': get_token_consumed('analyze_ui'),
                },
                'module_action_decision': {
                    '_response': actions.model_dump(mode='json'),
                    'is_subtask_optimal': None,
                    'steps_to_resolve_subtask_error': None,
                    'failed_task_reason': None,
                    'ui_change_history_screenshot': [e[1] for e in ui_change_history],
                    'ui_change_history_view_hierarchy': [e[0] for e in ui_change_history],
                    'ui_change_correct': None,
                    'fetch_time_consumed': get_time_consumed('App.fetch_ui_data'),
                    'apply_time_consumed': get_time_consumed('App.apply_action'),
                    'token_count': get_token_consumed('analyze_action'),
                },
                'module_transform_validation': {
                    '_response': mask_result.model_dump(mode='json') if mask_result else None,
                    'is_result_correct': None,
                    'false_positive_reason': None,
                    'false_negative_reason': None,
                    'time_consumed': get_time_consumed('App.fetch_mask'),
                    'token_count': get_token_consumed('detect_mask'),
                },
            })
            clear_time_consumed()
            clear_token_record()
            step_time = time.time()

        from app_window import App
        root, app = App.create_window(((result_callback, step_callback), get_screenshot, mask_detection, appium_ui, action))
        app.set_task(TASK)

        nonlocal close_window
        close_window = lambda: app.close_immediately()

        app_rounds['preprocess_time'] = time.time() - time_start

        restore_date_location()   # app may require correct time and date for https connection to work

        # Bring window to front
        root.lift()
        #root.iconify()  # Minimize window immediately
        root.attributes('-topmost', True)  # Or, always show the window
        root.attributes('-topmost', False)

        # Center window on screen, accounting for Windows taskbar
        root.update_idletasks()  # Ensure window dimensions are updated
        window_width = root.winfo_width()
        window_height = root.winfo_height()
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight() - 40  # Subtract typical Windows taskbar height
        center_x = int((screen_width - window_width) / 4)
        center_y = int((screen_height - window_height) / 4)
        root.geometry(f"{window_width}x{window_height}+{center_x}+{center_y}")

        # Start main loop 
        root.mainloop()

        close_window = False

        try:
            root.quit()
        except:
            ...
        try:
            root.destroy()
        except:
            ...

        del root; del app
    
        import os
        try:
            os.remove("screenshot.png")
        except:
            ...
    
    set_date_location()
    
    import itertools
    if isinstance(TASK, str):
        TASK = [(TASK, ROUND_BASE_TIMEOUT)]
    for _, (TASK, ROUND_TIMEOUT) in itertools.product(range(ROUND_COUNT), TASK):
        close_window = None
        def check_timeout():
            start_time = time.time()
            while start_time + ROUND_TIMEOUT > time.time():
                time.sleep(1)
                if close_window is False:
                    break     # already closed
            if close_window is None:
                logger.warning("Is stuck. Try force kill.")
                gbscript_sb.exports_sync.activeapp(APP_IDENT)
                fc.detach_and_kill()
                time.sleep(5)
            if close_window is None:
                raise RuntimeError("Is stuck. Unrecoverable.")
            if close_window:
                logger.warning("Round timeout, terminating...")
                close_window()
        check_thread = threading.Thread(target=check_timeout, daemon=True)
        check_thread.start()
        try:
            logger.info(f"Round task {TASK} timeout {ROUND_TIMEOUT}")
            round()
        except Exception as e:
            logger.exception(f"Error in round: {e}")
            if close_window:
                close_window()
            close_window = False
            raise e
        check_thread.join()
        import gc; gc.collect() # annoying Tk bug
        if result_trigger:
            # assuming this is successful
            break
    
    restore_date_location()

    if ipath and uninstall_then and UNINST_THEN:
        logger.info(f"Uninstall app {APP_IDENT} then from device")
        #run_process(['t3', 'app', 'uninstall', APP_IDENT])
        app_uninstall(APP_IDENT)
    
    app_attempts['time_consumed'] = time.time() - time_start

    with open(SAVE_STATE, 'w', encoding='utf-8') as f:
        import json
        json.dump(app_state, f, ensure_ascii=False)

def cleanup():
    sc.disconnect(); sc1.disconnect()
    gbscript_sb.unload()
    fc_sb.detach(); fc_sb.disconnect()
    fc.detach_and_kill(); fc.disconnect()
    zc.disconnect()
    appium.quit_driver()
    import gc; gc.collect()
    logger.info("Cleanup complete")

for EACH in BATCH_TASKS:
    for i in range(APP_COUNT):
        if isinstance(EACH, str):
            (APP_IDENT, TASK) = EACH, None
        else:
            (APP_IDENT, TASK) = EACH
        try:
            test_app(bool(i == 0), bool(i == APP_COUNT - 1))
        except Exception as e:
            logger.exception("Error testing app.")
            if 'the connection is closed' in repr(e) or 'error receiving data' in repr(e) or 'Unrecoverable.' in repr(e):
                with open('BATCH_TASKS.fin.txt', 'w') as f:
                    f.write('\n'.join(BATCH_TASKS_FIN))
                logger.critical("Unable to continue; restart the framework")
                cleanup()
                sleep(5)
                import os, sys
                os.execv(sys.executable, ['python'] + sys.argv)
            if bool(i == APP_COUNT -1) and UNINST_THEN:
                # try uninstall anyway
                try:
                    app_uninstall(APP_IDENT)
                except:
                    pass
        BATCH_TASKS_FIN.append(APP_IDENT)

cleanup()

