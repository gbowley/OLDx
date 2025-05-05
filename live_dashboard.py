# live_dashboard.py

# Manages live dashboard function. Includes periodic requests and CSV logging.

import time
import can
import threading
import queue
import csv # Added for CSV logging
import os # Added for checking file existence
from datetime import datetime # Added for timestamping logs
from typing import Optional, Set, Dict, Any, Callable, List
import traceback # For logging errors in parsing

# Import CanCommunication correctly
try:
    from can_communication import CanCommunication, ILiveDataProcessor, UDS_REQUEST_ID # Import UDS ID
    from log_data import mode22_live_data # Import Mode 22 definitions
except ImportError:
    print("Warning: Could not import from local files.")
    class CanCommunication: pass # Dummy for type hint
    class ILiveDataProcessor:
        TARGET_IDS: Set[int] = set()
        def process_message(self, msg): pass
    UDS_REQUEST_ID = 0x7E0
    mode22_live_data = []

# --- Define Data Keys ---
# 
NEW_LIVE_DATA_KEYS = [
    'lambdaB1', 'lambdaB2',
    'stftB1', 'ltftB1', 'stftB2', 'ltftB2',
    'fuelLearnDTB1', 'fuelLearnDTB2',
    'fuelLearnZ2B1', 'fuelLearnZ2B2',
    'fuelLearnZ3B1', 'fuelLearnZ3B2',
    'timingAdv', # Overall Timing Advance
    'knockCyl1', 'knockCyl2', 'knockCyl3', 'knockCyl4', 'knockCyl5', 'knockCyl6',
    'maf', 'throttlePos',
    'iat', 'aat', # Added IAT and AAT
]

# CAN IDs for BROADCAST Live Data Mapping
BROADCAST_LIVE_DATA_IDS: Dict[int, str] = {
    0xA8: 'parse_esp_abs',
    0x114: 'parse_ecu_114',
    0x202: 'parse_tcu_202',
    0x400: 'parse_cluster_400',
    0x401: 'parse_cluster_text',
    0x500: 'parse_time_date'
}

# OBD Mode 01 PIDs to request periodically
OBD_MODE_01_PIDS_TO_REQUEST: Dict[str, int] = {
    'stftB1': 0x06, 'ltftB1': 0x07,
    'stftB2': 0x08, 'ltftB2': 0x09,
    'timingAdv': 0x0E, # Overall timing advance
    'iat': 0x0F,       # Intake Air Temperature
    'maf': 0x10,
    'throttlePos': 0x11,
    'lambdaB1S1': 0x24, # Using Sensor 1 for Bank 1 Lambda
    'lambdaB2S1': 0x26, # Using Sensor 1 for Bank 2 Lambda
    'aat': 0x46,       # Ambient Air Temperature
}

# Mode 22 PIDs to request periodically
MODE_22_PIDS_TO_REQUEST: Dict[str, str] = {
    'fuelLearnDTB1': '022E', 'fuelLearnZ2B1': '0248', 'fuelLearnZ3B1': '0249',
    'fuelLearnDTB2': '0255', 'fuelLearnZ2B2': '025A', 'fuelLearnZ3B2': '025B',
    'knockCyl1': '0231', 'knockCyl2': '0231', 'knockCyl3': '0231','knockCyl4': '0231',
    'knockCyl5': '0256', 'knockCyl6': '0256',
}

# Build a lookup for Mode 22 scaling based on log_data.py
MODE_22_SCALING: Dict[str, Dict[str, Any]] = {}
for item in mode22_live_data:
    addr_parts = item.get('Address', '').split()
    if len(addr_parts) == 3 and addr_parts[0] == '22':
        did = addr_parts[1] + addr_parts[2]
        try:
            scale = float(item.get('SimpleScale', 1.0))
            offset = 0.0
            is_signed = item.get('isSigned', 'FALSE').upper() == 'TRUE'
            data_size = int(item.get('DataSize', 1))
            data_pos = int(item.get('DataPos', 0))
            MODE_22_SCALING[did] = {
                'scale': scale, 'offset': offset, 'signed': is_signed,
                'size': data_size, 'pos': data_pos,
                'text': item.get('Text', f'DID {did}')
            }
        except (ValueError, TypeError) as e:
            print(f"Warning: Could not parse scaling for Mode 22 DID {did}: {e}")

class LiveDashboard(ILiveDataProcessor):
    def __init__(self, can_comm: CanCommunication, update_callback: Callable[[Dict[str, Any]], None],
                 target_ids: Optional[Set[int]] = None, update_interval: float = 1.0):
        self.can_comm = can_comm
        self.update_callback = update_callback
        self.running = False
        self._last_update_time: Dict[int, float] = {}
        self._broadcast_update_interval: float = 0.25
        self.request_interval: float = update_interval
        self.live_data: Dict[str, Any] = {}
        self.request_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._log_func = getattr(self.can_comm, '_log', print)
        self.log_data_buffer: List[Dict[str, Any]] = [] # Buffer for CSV logging

        self.TARGET_IDS: Set[int] = set(BROADCAST_LIVE_DATA_IDS.keys())
        if OBD_MODE_01_PIDS_TO_REQUEST or MODE_22_PIDS_TO_REQUEST:
            self.TARGET_IDS.add(UDS_REQUEST_ID + 8) # Add 0x7E8

        self.parser_map: Dict[int, Callable[[bytes], Dict[str, Any]]] = {}
        for can_id, func_name in BROADCAST_LIVE_DATA_IDS.items():
            parser_method = getattr(self, func_name, None)
            if callable(parser_method):
                self.parser_map[can_id] = parser_method
            else:
                self._log_func(f"Warning: Parser method '{func_name}' not found for broadcast ID {can_id:X}")

        # Define all keys that might be logged or displayed
        self.all_data_keys = set(NEW_LIVE_DATA_KEYS)
        original_keys = ['rpm', 'apps', 'coolant', 'fuelLevel', 'gearAuto', 'brakeSwitch',
                         'sportSwitch', 'espIntervention', 'espAbsIntervention', 'mil',
                         'lowOilPressure', 'tpmsFault', 'shiftLight1', 'shiftLight2',
                         'shiftLight3', 'espSystemState', 'espAbsErrorState',
                         'espAsrErrorState', 'espErrorState', 'time', 'textMessage']
        self.all_data_keys.update(original_keys)
        self.log_header = ['Timestamp'] + sorted(list(self.all_data_keys)) # Define header for CSV

    def set_update_interval(self, interval: float):
        self.request_interval = max(0.1, interval)
        self._log_func(f"Live data request interval set to {self.request_interval:.2f}s")

    def clear_log_buffer(self):
        self.log_data_buffer = []

    def start(self) -> bool:
        if not self.can_comm or not self.can_comm.is_connected:
            self._log_func("Error: Cannot start dashboard, CAN not connected.")
            return False
        if self.running:
            self._log_func("Dashboard already running.")
            return True

        self._log_func("Starting live dashboard...")
        self._stop_event.clear()
        self.clear_log_buffer() # Clear buffer on start
        self.running = True

        initial_data = {key: "..." for key in self.all_data_keys}
        self.live_data.update(initial_data)
        if callable(self.update_callback):
             self.update_callback(initial_data)

        if OBD_MODE_01_PIDS_TO_REQUEST or MODE_22_PIDS_TO_REQUEST:
            self.request_thread = threading.Thread(target=self._request_loop, daemon=True, name="DashboardRequestThread")
            self.request_thread.start()
            self._log_func("Request thread started.")
        else:
            self._log_func("No request-based PIDs configured.")

        ids_str = ", ".join(f'{tid:X}' for tid in sorted(list(self.TARGET_IDS)))
        self._log_func(f"Live dashboard active (Processing IDs: {ids_str}).")
        return True

    def stop(self):
        """Stops the dashboard and associated threads. CSV save is now external."""
        if not self.running:
            return
        self._log_func("Stopping live dashboard processing...")
        self._stop_event.set() # Signal the request thread to stop

        if self.request_thread and self.request_thread.is_alive():
            self._log_func("Waiting for request thread to stop...")
            self.request_thread.join(timeout=self.request_interval + 0.5)
            if self.request_thread.is_alive():
                self._log_func("Warning: Dashboard request thread did not stop cleanly.")
            else:
                self._log_func("Request thread stopped.")
        self.request_thread = None
        self.running = False
        # CSV saving is triggered by stop_dashboard_action in main_gui
        self._log_func("Live dashboard stopped.")


    def save_log_to_csv(self) -> Optional[str]:
        # Saves the buffered log data to a uniquely named CSV file.
        if not self.log_data_buffer:
            self._log_func("Log buffer is empty, nothing to save.")
            return None

        base_filename = "livedata_log"
        extension = ".csv"
        counter = 1
        filename = f"{base_filename}_{counter}{extension}"

        # Find the next available filename
        while os.path.exists(filename):
            counter += 1
            filename = f"{base_filename}_{counter}{extension}"

        self._log_func(f"Attempting to save live data log to {filename}...")
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                # Use the predefined header derived from all_data_keys
                writer = csv.DictWriter(csvfile, fieldnames=self.log_header, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(self.log_data_buffer)
            self._log_func(f"Successfully saved {len(self.log_data_buffer)} data points.")
            # Keep buffer until next start
            # self.clear_log_buffer() # Clear buffer only on start now
            return filename
        except IOError as e:
            self._log_func(f"Error saving log file '{filename}': {e}")
        except Exception as e:
            self._log_func(f"Unexpected error saving CSV log: {e}")
            self._log_func(traceback.format_exc())
        return None

    def _request_loop(self):
        self._log_func("Request loop initiated.")
        all_requests = []
        for key, pid in OBD_MODE_01_PIDS_TO_REQUEST.items():
             # Allow multiple keys to request the same PID if needed (e.g., lambda sensors)
             all_requests.append({'mode': 0x01, 'pid': pid, 'key': key}) # Include key for potential logging

        requested_dids = set()
        for key, did in MODE_22_PIDS_TO_REQUEST.items():
            if did not in requested_dids:
                # Only add unique DIDs to request list, parser handles multiple keys per DID
                all_requests.append({'mode': 0x22, 'did': did, 'key': f"did_{did}"})
                requested_dids.add(did)

        if not all_requests:
            self._log_func("Request loop: No OBD/Mode22 PIDs configured.")
            return

        request_index = 0
        while not self._stop_event.is_set():
            start_time = time.monotonic()

            if not self.can_comm or not self.can_comm.is_connected:
                self._log_func("Request loop: CAN disconnected, pausing.")
                self._stop_event.wait(2.0)
                continue

            if all_requests:
                current_request = all_requests[request_index % len(all_requests)]
                if current_request['mode'] == 0x01:
                    pid = current_request['pid']
                    req_data = [0x02, 0x01, pid]
                    self.can_comm.send_command(
                        f"obd_req_{pid:02X}", req_id=UDS_REQUEST_ID, data=req_data,
                        timeout=0.5, expected_response_service_id=0x41
                    )
                elif current_request['mode'] == 0x22:
                    did_str = current_request['did']
                    try:
                        did_hi = int(did_str[0:2], 16)
                        did_lo = int(did_str[2:4], 16)
                        req_data = [0x03, 0x22, did_hi, did_lo]
                        self.can_comm.send_command(
                            f"m22_req_{did_str}", req_id=UDS_REQUEST_ID, data=req_data,
                            timeout=0.5, expected_response_service_id=0x62
                        )
                    except ValueError:
                        self._log_func(f"Error: Invalid DID format '{did_str}'")

                request_index += 1

            elapsed = time.monotonic() - start_time
            num_reqs = len(all_requests) if all_requests else 1
            sleep_duration = max(0.02, (self.request_interval / num_reqs) - elapsed)
            self._stop_event.wait(sleep_duration)

        self._log_func("Request loop finished.")

    def _should_update(self, can_id: int) -> bool:
        if can_id not in BROADCAST_LIVE_DATA_IDS: return True
        now = time.monotonic()
        last_time = self._last_update_time.get(can_id, 0)
        if (now - last_time) >= self._broadcast_update_interval:
            self._last_update_time[can_id] = now
            return True
        return False

    def process_message(self, msg: can.Message):
        if not self.running: return
        arbitration_id = msg.arbitration_id
        data_bytes = bytes(msg.data) if hasattr(msg, 'data') and msg.data is not None else b''

        if arbitration_id in self.parser_map:
            if self._should_update(arbitration_id):
                parser_func = self.parser_map.get(arbitration_id)
                if parser_func:
                    try:
                        updates = parser_func(data_bytes)
                        if updates and isinstance(updates, dict):
                            self._send_updates(updates)
                    except Exception as e:
                        self._log_func(f"Error parsing broadcast ID {arbitration_id:03X}: {type(e).__name__} - {e}")

        elif arbitration_id == UDS_REQUEST_ID + 8:
             try:
                 sid_index = -1; response_sid = 0
                 if len(data_bytes) >= 2 and data_bytes[0] & 0xF0 == 0x00: sid_index = 1
                 elif len(data_bytes) >= 3 and data_bytes[0] & 0xF0 == 0x10: sid_index = 2
                 elif len(data_bytes) >= 3 and data_bytes[0] == 0x00: sid_index = 2
                 if sid_index != -1 and len(data_bytes) > sid_index:
                     response_sid = data_bytes[sid_index]
                     payload_start = sid_index + 1
                     payload = data_bytes[payload_start:]
                     updates = {}
                     if response_sid == 0x41: updates = self._parse_obd_mode01_response(payload)
                     elif response_sid == 0x62: updates = self._parse_mode22_response(payload)
                     if updates: self._send_updates(updates)
             except Exception as e:
                 self._log_func(f"Error parsing diagnostic response ID {arbitration_id:03X}: {type(e).__name__} - {e}")

    def _send_updates(self, updates: Dict[str, Any]):
        # [ Updated to include timestamp in log buffer entry ]
        changed_data_for_gui = {}
        # Create log entry *before* updating internal state to capture snapshot
        current_log_entry = {'Timestamp': datetime.now().isoformat(sep=' ', timespec='milliseconds')}
        # Populate with *current* live_data state first
        for key in self.log_header:
             if key != 'Timestamp':
                 current_log_entry[key] = self.live_data.get(key, None)

        # Update internal state and identify changes for GUI
        for key, value in updates.items():
            if key in self.all_data_keys:
                if self.live_data.get(key) != value:
                    changed_data_for_gui[key] = value
                    self.live_data[key] = value # Update internal state
                # Update the log entry with the new value regardless of change
                current_log_entry[key] = value

        # Add the potentially updated snapshot to the buffer
        self.log_data_buffer.append(current_log_entry)

        # Send only changed data to the GUI callback
        if changed_data_for_gui:
            if callable(self.update_callback):
                try:
                    self.update_callback(changed_data_for_gui)
                except Exception as cb_e:
                     self._log_func(f"Error in dashboard update callback: {cb_e}")
            else:
                 self._log_func("Warning: Live dashboard update_callback is not callable.")

    # --- OBD Mode 01 Parser ---
    def _parse_obd_mode01_response(self, payload: bytes) -> Dict[str, Any]:
        # [ Includes IAT, AAT, Overall Timing, Lambda Debug ]
        updates = {}
        if len(payload) < 1: return updates

        pid = payload[0]
        pid_data = payload[1:]
        self._log_func(f"Parsing OBD Mode 01 PID {pid:02X} Response: {payload.hex()}")

        try:
            if pid == 0x06 and len(pid_data) >= 1: updates['stftB1'] = (pid_data[0] - 128) * 100.0 / 128.0
            elif pid == 0x07 and len(pid_data) >= 1: updates['ltftB1'] = (pid_data[0] - 128) * 100.0 / 128.0
            elif pid == 0x08 and len(pid_data) >= 1: updates['stftB2'] = (pid_data[0] - 128) * 100.0 / 128.0
            elif pid == 0x09 and len(pid_data) >= 1: updates['ltftB2'] = (pid_data[0] - 128) * 100.0 / 128.0
            elif pid == 0x0E and len(pid_data) >= 1:
                 updates['timingAdv'] = (pid_data[0] / 2.0) - 64.0
                 self._log_func(f"  Timing Adv Raw: {pid_data[0]}, Calculated: {updates['timingAdv']}")
            elif pid == 0x0F and len(pid_data) >= 1:
                 updates['iat'] = float(pid_data[0] - 40)
                 self._log_func(f"  IAT Raw: {pid_data[0]}, Calculated: {updates['iat']}")
            elif pid == 0x10 and len(pid_data) >= 2: updates['maf'] = ((pid_data[0] * 256.0) + pid_data[1]) / 100.0
            elif pid == 0x11 and len(pid_data) >= 1: updates['throttlePos'] = pid_data[0] * 100.0 / 255.0
            elif pid == 0x24 and len(pid_data) >= 4:
                ratio = ((pid_data[0] * 256.0) + pid_data[1]) / 32768.0 * 2.0
                updates['lambdaB1'] = ratio
                self._log_func(f"  Lambda B1 Raw: {pid_data[:2].hex()}, Calculated Ratio: {ratio}")
            elif pid == 0x26 and len(pid_data) >= 4:
                ratio = ((pid_data[0] * 256.0) + pid_data[1]) / 32768.0 * 2.0
                updates['lambdaB2'] = ratio
                self._log_func(f"  Lambda B2 Raw: {pid_data[:2].hex()}, Calculated Ratio: {ratio}")
            elif pid == 0x46 and len(pid_data) >= 1:
                 updates['aat'] = float(pid_data[0] - 40)
                 self._log_func(f"  AAT Raw: {pid_data[0]}, Calculated: {updates['aat']}")
        except IndexError: self._log_func(f"Index error parsing OBD PID {pid:02X} payload {payload.hex()}")
        except Exception as e: self._log_func(f"Error parsing OBD PID {pid:02X}: {e}")
        return updates

    # --- UDS Mode 22 Parser ---
    def _parse_mode22_response(self, payload: bytes) -> Dict[str, Any]:
        updates = {}
        if len(payload) < 2: return updates

        did_hi = payload[0]
        did_lo = payload[1]
        did_str = f"{did_hi:02X}{did_lo:02X}".upper()
        did_data = payload[2:]

        scaling_info = MODE_22_SCALING.get(did_str)
        self._log_func(f"Parsing Mode 22 DID {did_str} Response: {payload.hex()}")

        try:
            if did_str == '0231': # Knock Retard Cyl 1-4
                if len(did_data) >= 1: updates['knockCyl1'] = did_data[0] * 0.25
                if len(did_data) >= 2: updates['knockCyl2'] = did_data[1] * 0.25
                if len(did_data) >= 3: updates['knockCyl3'] = did_data[2] * 0.25
                if len(did_data) >= 4: updates['knockCyl4'] = did_data[3] * 0.25
                self._log_func(f"  Knock Retard (0231): {updates}")
            elif did_str == '0256': # Knock Retard Cyl 5-6
                if len(did_data) >= 1: updates['knockCyl5'] = did_data[0] * 0.25
                if len(did_data) >= 2: updates['knockCyl6'] = did_data[1] * 0.25
                self._log_func(f"  Knock Retard (0256): {updates}")
            elif scaling_info: # Handle other DIDs based on scaling info
                key_to_update = None
                for k, req_did in MODE_22_PIDS_TO_REQUEST.items():
                     if req_did == did_str:
                         if did_str not in ['0231', '0256'] or 'knockCyl' not in k:
                             key_to_update = k
                             break

                if key_to_update:
                    pos = scaling_info['pos']
                    size = scaling_info['size']
                    if len(did_data) >= pos + size:
                        raw_bytes = did_data[pos : pos + size]
                        raw_value = int.from_bytes(raw_bytes, byteorder='big', signed=scaling_info['signed'])
                        scaled_value = (raw_value * scaling_info['scale']) + scaling_info['offset']
                        updates[key_to_update] = scaled_value
                        self._log_func(f"  Parsed DID {did_str} ({scaling_info['text']}) for key '{key_to_update}': {scaled_value}")
                    else:
                        self._log_func(f"Warning: Insufficient data length for DID {did_str}. Got {len(did_data)}, need {pos+size}")
            # else: # Log unhandled DIDs if needed
            #      self._log_func(f"Received unhandled/unscaled Mode 22 DID {did_str}")

        except IndexError:
            self._log_func(f"Index error parsing Mode 22 DID {did_str} with payload {payload.hex()}")
        except Exception as e:
            self._log_func(f"Error parsing Mode 22 DID {did_str}: {e}")

        return updates

    # --- Original Parsers ---
    def parse_esp_abs(self, data: bytes) -> Dict[str, Any]:
        updates = {}
        if len(data) >= 2:
            updates['espAbsErrorState'] = (data[0] >> 0) & 1; updates['espAbsIntervention'] = (data[0] >> 1) & 1
            updates['espAsrErrorState'] = (data[0] >> 2) & 1; updates['espAsrIntervention'] = (data[0] >> 3) & 1
            updates['espAsrLamp'] = (data[0] >> 4) & 1; updates['espErrorState'] = (data[0] >> 5) & 1
            updates['espIntervention'] = (data[0] >> 6) & 1; updates['espSystemState'] = data[1] & 0b11
            updates['brakeLamp'] = (data[1] >> 2) & 1; updates['sportLamp'] = (data[1] >> 3) & 1
        return updates

    def parse_ecu_114(self, data: bytes) -> Dict[str, Any]:
        updates = {}
        if len(data) >= 6:
            try:
                rpm_raw = (data[1] << 8) + data[0]; updates['rpm'] = int(round(rpm_raw / 4.0, 0)) # Ensure int
                updates['apps'] = round(data[2] / 2.55, 1)
                updates['espAndAsrOff'] = (data[4] >> 6) & 1; updates['sportSwitch'] = (data[4] >> 7) & 1
                updates['brakeSwitch'] = data[5] & 0b11
            except IndexError: return {}
        return updates

    def parse_tcu_202(self, data: bytes) -> Dict[str, Any]:
        updates = {}
        if len(data) >= 1:
            gear_val = data[0] & 0b1111
            if gear_val == 0: gear_str = "P"
            elif gear_val == 1: gear_str = "R"
            elif gear_val == 2: gear_str = "N"
            elif 3 <= gear_val <= 15: gear_str = str(gear_val - 2)
            else: gear_str = "?"
            updates['gearAuto'] = gear_str
        return updates

    def parse_cluster_400(self, data: bytes) -> Dict[str, Any]:
        updates = {}
        if len(data) >= 7:
            try:
                updates['fuelLevel'] = round(data[4] / 2.55, 1); updates['coolant'] = round((data[5] / 1.6) - 40, 1)
                updates['usa'] = (data[6] >> 0) & 1; updates['tpmsFault'] = (data[6] >> 1) & 1
                updates['lowOilPressure'] = (data[6] >> 3) & 1; updates['mil'] = (data[6] >> 4) & 1
                updates['shiftLight3'] = (data[6] >> 5) & 1; updates['shiftLight2'] = (data[6] >> 6) & 1
                updates['shiftLight1'] = (data[6] >> 7) & 1
                if len(data) >= 8:
                    updates['rearFogBulbCheck'] = (data[7] >> 2) & 1; updates['coolantHot'] = (data[7] >> 3) & 1
                    updates['spanner'] = (data[7] >> 7) & 1
            except IndexError: return {}
        return updates

    def parse_cluster_text(self, data: bytes) -> Dict[str, Any]:
        updates = {};
        if len(data) >= 2:
            try:
                message = data[1:].decode('ascii', errors='ignore').replace('\x00','').strip()
                if self.live_data.get('textMessage') != message:
                    updates['textMessage'] = message
            except Exception as e: pass
        return updates

    def parse_time_date(self, data: bytes) -> Dict[str, Any]:
        updates = {}
        if len(data) >= 7:
            try:
                seconds = data[0]; minutes = data[1]; hours = data[2]
                day = data[3]; month = data[4]; year_offset = data[6]
                if year_offset < 100: year = 2000 + year_offset
                else: year = (data[6] << 8) + data[7] if len(data) >= 8 else 1999
                if not (0 <= seconds <= 59 and 0 <= minutes <= 59 and 0 <= hours <= 23 and 1 <= day <= 31 and 1 <= month <= 12 and 2000 <= year <= 2099): raise ValueError("Out of range")
                time_str = f"{year:04d}-{month:02d}-{day:02d} {hours:02d}:{minutes:02d}:{seconds:02d}"
                if self.live_data.get('time') != time_str:
                    updates['time'] = time_str
            except (IndexError, ValueError):
                 if self.live_data.get('time') != "Date/Time Error": updates['time'] = "Date/Time Error"
        return updates