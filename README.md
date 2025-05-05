
# Open Lotus Diagnostics Tool - OLDx

## Overview

This application provides diagnostic capabilities for Lotus vehicles by communicating directly with the CAN bus. It allows users to read and clear fault codes from modules, view live data streams, identify vehicle details via VIN, and retrieve performance metrics logged by the ECU.

## --- USE AT YOUR OWN RISK ---

## Compatibility

**Vehicle:** This application is tested working on the V6 Exige. It is likely compatible with the Evora, as well as CAN capable late Elise and Exige models.
Emira compatibility is not tested but possible with some limitations.

**Interface:** This application is written for and tested with the [Korlan USB2CAN](https://www.8devices.com/products/korlan) cable and associated drivers.

## Features

* **CAN Bus Communication:** Connects to the vehicle using `usb2can` and `python-can`. Supports standard CAN and ISO-TP for multi-frame diagnostic messages.
* **Vehicle Identification:** Retrieves the Vehicle Identification Number (VIN) and identifies the vehicle model, year, market, and relevant ECU/module programs based on an internal database (`vehicles.py`).
* **Diagnostic Trouble Code (DTC) Management:**
    * Reads confirmed and pending fault codes from Engine Control Module (ECM), Transmission Control Unit (TCU, if installed), and Anti-lock Braking System (ABS) modules.
    * Supports UDS, KWP2000 (for specific ABS modules), and OBD-II standard fault codes.
    * Clears fault codes from supported modules.
    * Looks up descriptions for known fault codes (`known_faults.py`).
* **Live Data Dashboard:**
    * Displays real-time data broadcasted on the CAN bus (e.g., RPM, pedal position, coolant temp, gear).
    * Requests data on specific OBD Mode 01 and UDS Mode 22 PIDs at user defined frequency (e.g., fuel trims, lambda values, timing advance, knock retard, IAT, AAT).
    * Logs live data sessions to CSV files for later analysis.
* **Performance Data Retrieval:** Reads historical performance metrics logged by the ECU, such as time spent at specific RPM/speed/TPS ranges, max speed events, standing start times, and low oil pressure event details. This could prove useful when buying a car.

## Installation

1.  **Python:** Ensure you have Python 3 installed. The recommended install is [3.9.7](https://www.python.org/downloads/release/python-397/) for environment compatibility with [Lotus Flasher](https://github.com/Alcantor/LotusECU-T4e)
2.  **Dependencies:** Install the required Python libraries. The primary dependencies are `python-can`, and `pyserial`. Open an elevated command prompt and run the following.
    ```bash
    pip install python-can
    pip install pyserial
    # Add any other specific dependencies if identified, e.g., for a specific CAN interface backend
    # pip install can-isotp # (Potentially needed depending on python-can version and usage)
    ```
3.  **CAN Interface Driver 1:** Install the necessary drivers for the Korlan Adapter, including the [Windows Driver](https://drive.google.com/drive/folders/1gXWpuP20U2mhcW6IqtwhRo0PY9ZusSYv)
4. **CAN Interface Driver 2:** Install the [USB2CAN](https://drive.google.com/file/d/1_xSpR1bGE3OQN6w0EG9WmrvtgatyQa05/view) driver by placing `usb2can.dll` in your Python install directory.

## Setup

1.  **Hardware:** Connect the USB interface to your computer and the OBD-II interface to the vehicle's OBD-II port.
2.  **Configuration:**
    * Launch the application (`main_gui.py`).
    * In the "Connection" section:
        * (Optional) Select the correct **Interface** type from the dropdown (e.g., `usb2can`).
        * (Optional) Enter the appropriate **Channel** for your interface (e.g., the serial number above the QR code on your `usb2can` device). Manually inputting the interface ID should not be necessary unless multiple adapters are connected.
        * Select the correct **Bitrate** (typically 500000 for modern Lotus, for 1000000 compatibility see [Lotus Flasher](https://github.com/Alcantor/LotusECU-T4e)).

## Utilisation

1.  **Connect:** Click the "Connect" button. The status label will indicate if the connection was successful.
2.  **Identify Vehicle:** Click "Get VIN / Identify". The application will attempt to read the VIN and look up the vehicle details. If automatic reading fails, you may be prompted for manual entry. Vehicle details will populate in the top section and the 'Vehicle Details' tab.
3.  **Read Faults:** Navigate to the 'Diagnostics & Faults' tab and click "Read All Faults". The application will query the ECM, TCU, and ABS (using appropriate protocols based on identified vehicle info) and display the results.
4.  **Clear Faults:** After reviewing faults, click "Clear All Faults" on the same tab. *Note: A full ignition cycle (off/on) is usually required after clearing faults for them to be fully reset.* Re-read faults after the cycle to confirm.
5.  **Live Dashboard:**
    * Go to the 'Live Dashboard' tab.
    * Select the desired **Update Freq** (how often the tool *requests* data;). Higher update frequency will improve log resolution at the cost of increased CANbus load (high frequencies not yet tested).
    * Click "Start Dashboard". Live values will populate the fields.
    * Click "Stop Dashboard" to end the live session. The buffered data will be saved to CSV file in the application's directory. Later sessions will be saved separately.
6.  **Performance Data:** Go to the 'Performance Data' tab and click "Read Performance Data". The application will query the ECU for logged historical metrics and display them.
7.  **Log (Developer):** The 'Log' tab displays timestamped messages about application operations, connection status, errors, and diagnostic steps. Please provide full logs when reporting errors.

## Limitations

* **Vehicle Coverage:** Primarily supports Lotus Elise, Exige, and Evora models based on the data in `vehicles.py`. Support for other models (like Emira V6) is not tested.
* **Module Support:** While ECM, and ABS are currently tested, communication success can vary depending on the specific module variant and vehicle year. Some modules might require specific diagnostic sessions or protocols not fully implemented for all variants. I need to test the tool on more vehicles to confirm compatibility across more modules.
* **Development Release:** This application is the result of a couple of days of development and tested on only one vehicle, as such it is highly likely that I have not accounted for various issues which may arise when the application is used on other vehicles.

## Planned Updates / Future Work

* Implement more advanced diagnostic routines (e.g., actuator tests, adaptation resets).
* Add support for SRS, TPMS modules.
* Add support for module read/write.
* Investigate support for newer vehicle architectures (e.g., Emira).
 
## Changelog

* 05/05/2025 - Initial developer release. Diagnostics of ECM/ABS units tested working on Exige V6S. Basic fixed function live data capture and CSV logging implemented. Full read of performance data implemented.

