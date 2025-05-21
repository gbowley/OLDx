@echo off

REM Check if the script is already running minimized
IF "%~1"=="__MINIMIZED__" (
    REM Already minimized, remove the parameter and go to main logic
    SHIFT
    goto main_logic
)

REM Not minimized, so relaunch this script minimized and exit the current instance
REM Using CMD /C to ensure the new window properly executes the batch file and its arguments.
REM The title "Launching App Minimized" is for the new window.
START "Launching App Minimized" /MIN cmd /C ""%~f0" __MINIMIZED__ %*"
EXIT /B

:main_logic
SETLOCAL ENABLEDELAYEDEXPANSION

REM --- Configuration ---
SET SCRIPT_TO_RUN=main_gui.py
SET BATCH_LOG_FILE=launcher_log.txt
SET PYTHON_LOG_FILE=program_log.txt
SET USER_PYTHON_PATH_RAW=
SET USER_PYTHON_PATH_CLEANED=

REM Clear previous log files
IF EXIST "%BATCH_LOG_FILE%" DEL "%BATCH_LOG_FILE%"
IF EXIST "%PYTHON_LOG_FILE%" DEL "%PYTHON_LOG_FILE%"

echo Starting Batch Script Execution (Minimized Instance)... > "%BATCH_LOG_FILE%"
echo Timestamp: %DATE% %TIME% >> "%BATCH_LOG_FILE%"
echo. >> "%BATCH_LOG_FILE%"

SET PYTHON_EXECUTABLE_CMD=py -3.9
echo Attempting to use default PYTHON_EXECUTABLE_CMD: %PYTHON_EXECUTABLE_CMD% >> "%BATCH_LOG_FILE%"

echo Verifying Python command by running: %PYTHON_EXECUTABLE_CMD% --version >> "%BATCH_LOG_FILE%"
echo --- Output from Python version check (py -3.9) START --- >> "%BATCH_LOG_FILE%"
%PYTHON_EXECUTABLE_CMD% --version >> "%BATCH_LOG_FILE%" 2>&1
SET PYTHON_VERSION_CHECK_EC=%ERRORLEVEL%
echo --- Output from Python version check (py -3.9) END --- >> "%BATCH_LOG_FILE%"
echo Python version check command (py -3.9) Errorlevel: %PYTHON_VERSION_CHECK_EC% >> "%BATCH_LOG_FILE%"

echo DEBUG: Just before IF/ELSE structure. PYTHON_VERSION_CHECK_EC is %PYTHON_VERSION_CHECK_EC% >> "%BATCH_LOG_FILE%"

IF "%PYTHON_VERSION_CHECK_EC%"=="0" (
    echo DEBUG: Initial 'py -3.9' version check was successful. >> "%BATCH_LOG_FILE%"
    goto py_39_check_ok
) ELSE (
    echo DEBUG: Initial 'py -3.9' version check FAILED. Errorlevel: %PYTHON_VERSION_CHECK_EC%. >> "%BATCH_LOG_FILE%"
    goto py_39_check_fail
)

:py_39_check_fail
    echo DEBUG: Entered py_39_check_fail block. >> "%BATCH_LOG_FILE%"
    echo WARNING: The command '%PYTHON_EXECUTABLE_CMD% --version' failed (Errorlevel: %PYTHON_VERSION_CHECK_EC%). >> "%BATCH_LOG_FILE%"
    echo This means '%PYTHON_EXECUTABLE_CMD%' is likely not working correctly on your system. >> "%BATCH_LOG_FILE%"
    echo.
    echo Python 3.9 (via py -3.9) not found or failed.
    SET /P USER_PYTHON_PATH_RAW="Please enter the FULL path to your Python 3.9 python.exe (e.g., C:\Python39\python.exe) and press Enter: "
    echo User entered raw path: "!USER_PYTHON_PATH_RAW!" >> "%BATCH_LOG_FILE%"

    IF "!USER_PYTHON_PATH_RAW!"=="" (
        echo DEBUG: User raw path is empty. >> "%BATCH_LOG_FILE%"
        echo ERROR: No path entered by user. Exiting. >> "%BATCH_LOG_FILE%"
        echo No path entered. Cannot proceed.
        goto end_script
    )

    REM Clean quotes from user input
    SET USER_PYTHON_PATH_CLEANED=!USER_PYTHON_PATH_RAW:"=!
    echo User cleaned path (quotes removed): "!USER_PYTHON_PATH_CLEANED!" >> "%BATCH_LOG_FILE%"

    IF NOT EXIST "!USER_PYTHON_PATH_CLEANED!" (
        echo DEBUG: User cleaned path does not exist. >> "%BATCH_LOG_FILE%"
        echo ERROR: User-provided Python path does not exist: "!USER_PYTHON_PATH_CLEANED!". Exiting. >> "%BATCH_LOG_FILE%"
        echo The path you entered does not exist: "!USER_PYTHON_PATH_CLEANED!"
        echo Please ensure it's the correct full path to python.exe.
        goto end_script
    )
    
    IF /I "!USER_PYTHON_PATH_CLEANED:~-10!" NEQ "python.exe" (
        echo DEBUG: User cleaned path does not end with python.exe. Path was: "!USER_PYTHON_PATH_CLEANED!" >> "%BATCH_LOG_FILE%"
        echo WARNING: User-provided path "!USER_PYTHON_PATH_CLEANED!" does not end with python.exe. Attempting to use it anyway. >> "%BATCH_LOG_FILE%"
        echo The path you entered ("!USER_PYTHON_PATH_CLEANED!") does not appear to be python.exe. It will be used as is.
    )

    SET PYTHON_EXECUTABLE_CMD="!USER_PYTHON_PATH_CLEANED!"
    echo DEBUG: Set PYTHON_EXECUTABLE_CMD to user path: %PYTHON_EXECUTABLE_CMD% >> "%BATCH_LOG_FILE%"
    echo Now attempting to use user-provided PYTHON_EXECUTABLE_CMD: %PYTHON_EXECUTABLE_CMD% >> "%BATCH_LOG_FILE%"

    echo Verifying user-provided Python command by running: %PYTHON_EXECUTABLE_CMD% --version >> "%BATCH_LOG_FILE%"
    echo --- Output from Python version check (user path) START --- >> "%BATCH_LOG_FILE%"
    %PYTHON_EXECUTABLE_CMD% --version >> "%BATCH_LOG_FILE%" 2>&1
    SET PYTHON_VERSION_CHECK_EC_USER=%ERRORLEVEL%
    echo --- Output from Python version check (user path) END --- >> "%BATCH_LOG_FILE%"
    echo Python version check command (user path) Errorlevel: %PYTHON_VERSION_CHECK_EC_USER% >> "%BATCH_LOG_FILE%"

    IF "%PYTHON_VERSION_CHECK_EC_USER%"=="0" (
        echo DEBUG: User path version check successful. >> "%BATCH_LOG_FILE%"
        echo User-provided Python command '%PYTHON_EXECUTABLE_CMD% --version' successful. >> "%BATCH_LOG_FILE%"
        goto continue_script_execution
    ) ELSE (
        echo DEBUG: User path version check failed. Errorlevel: %PYTHON_VERSION_CHECK_EC_USER% >> "%BATCH_LOG_FILE%"
        echo ERROR: User-provided Python command '%PYTHON_EXECUTABLE_CMD% --version' also failed (Errorlevel: %PYTHON_VERSION_CHECK_EC_USER%). >> "%BATCH_LOG_FILE%"
        echo The path you provided ('!USER_PYTHON_PATH_CLEANED!') could not be verified as a working Python 3.9 interpreter.
        echo Please check the path and ensure it is correct.
        goto end_script
    )

:py_39_check_ok
echo DEBUG: Reached py_39_check_ok label. PYTHON_EXECUTABLE_CMD is still '%PYTHON_EXECUTABLE_CMD%' >> "%BATCH_LOG_FILE%"
echo Default Python command '%PYTHON_EXECUTABLE_CMD% --version' (py -3.9) successful. >> "%BATCH_LOG_FILE%"
goto continue_script_execution

:continue_script_execution
echo DEBUG: Reached continue_script_execution label. PYTHON_EXECUTABLE_CMD is '%PYTHON_EXECUTABLE_CMD%' >> "%BATCH_LOG_FILE%"

REM Change to the directory where this batch file is located.
echo Changing directory to: %~dp0 >> "%BATCH_LOG_FILE%"
cd /d "%~dp0"
echo Current directory: %CD% >> "%BATCH_LOG_FILE%"

IF NOT EXIST "%SCRIPT_TO_RUN%" (
    echo ERROR: Python script "%SCRIPT_TO_RUN%" not found in %CD%. >> "%BATCH_LOG_FILE%"
    goto end_script
) ELSE (
    echo Found script: %CD%\%SCRIPT_TO_RUN% >> "%BATCH_LOG_FILE%"
)

echo. >> "%BATCH_LOG_FILE%"
echo Attempting to launch Python script: %PYTHON_EXECUTABLE_CMD% %SCRIPT_TO_RUN% >> "%BATCH_LOG_FILE%"
echo --- Python Script Output (stdout and stderr) will be logged to %PYTHON_LOG_FILE% --- >> "%BATCH_LOG_FILE%"
echo. >> "%BATCH_LOG_FILE%"

call %PYTHON_EXECUTABLE_CMD% %SCRIPT_TO_RUN% > "%PYTHON_LOG_FILE%" 2>&1
SET PYTHON_EXIT_CODE=%ERRORLEVEL%

echo. >> "%BATCH_LOG_FILE%"
echo Python script execution finished. >> "%BATCH_LOG_FILE%"
echo Python exit code: %PYTHON_EXIT_CODE% >> "%BATCH_LOG_FILE%"

IF "%PYTHON_EXIT_CODE%" NEQ "0" (
    echo. >> "%BATCH_LOG_FILE%"
    echo "--- ERROR DETAILS ---" >> "%BATCH_LOG_FILE%"
    echo The Python script exited with an error (Error Code: %PYTHON_EXIT_CODE%). >> "%BATCH_LOG_FILE%"
    echo Please check "%PYTHON_LOG_FILE%" for Python error messages. >> "%BATCH_LOG_FILE%"
    echo "--- END ERROR DETAILS ---" >> "%BATCH_LOG_FILE%"
    echo.
    echo PYTHON SCRIPT EXITED WITH AN ERROR (Code: %PYTHON_EXIT_CODE%).
    echo Check %PYTHON_LOG_FILE% and %BATCH_LOG_FILE% for details.
) ELSE (
    echo. >> "%BATCH_LOG_FILE%"
    echo Python script completed successfully. >> "%BATCH_LOG_FILE%"
    echo.
    echo Python script completed. See %PYTHON_LOG_FILE% for any script output.
)

:end_script
echo. >> "%BATCH_LOG_FILE%"
echo Batch script finished. >> "%BATCH_LOG_FILE%"

echo.
echo Batch script execution complete.
echo Check %BATCH_LOG_FILE% for batch execution details.
echo Check %PYTHON_LOG_FILE% for Python script output/errors.
pause
