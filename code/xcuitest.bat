@echo off
REM https://github.com/alibaba/tidevice/issues/277
REM https://github.com/alibaba/tidevice/issues/377
.venv\Scripts\tidevice xcuitest -B com.1xample.WebDriverAgentRunner.xctrunner -e USE_PORT:8100
pause