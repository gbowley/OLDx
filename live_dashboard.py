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

# Import CanCommunication
try:
    from can_communication import CanCommunication, ILiveDataProcessor, UDS_REQUEST_ID, PCI_TYPE_SF, PCI_TYPE_FF # <--- Added PCI type imports here
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
# Combined from original and requested PIDs
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
            offset = 0.0 # Assuming offset is 0 unless specified differently
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
        self._broadcast_update_interval: float = 0.25 # Throttle for broadcast updates (seconds)
        self.request_interval: float = update_interval # Target interval for *full cycle* of requests
        self.live_data: Dict[str, Any] = {}
        self.request_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._log_func = getattr(self.can_comm, '_log', print)
        self.log_data_buffer: List[Dict[str, Any]] = [] # Buffer for CSV logging

        # Define target IDs for message processing
        self.TARGET_IDS: Set[int] = set(BROADCAST_LIVE_DATA_IDS.keys())
        if OBD_MODE_01_PIDS_TO_REQUEST or MODE_22_PIDS_TO_REQUEST:
            self.TARGET_IDS.add(UDS_REQUEST_ID + 8) # Add UDS Response ID 0x7E8

        # Map broadcast IDs to parser functions
        self.parser_map: Dict[int, Callable[[bytes], Dict[str, Any]]] = {}
        for can_id, func_name in BROADCAST_LIVE_DATA_IDS.items():
            parser_method = getattr(self, func_name, None)
            if callable(parser_method):
                self.parser_map[can_id] = parser_method
            else:
                self._log_func(f"Warning: Parser method '{func_name}' not found for broadcast ID {can_id:X}")

        # Define all possible keys for the log header and internal state
        self.all_data_keys = set(NEW_LIVE_DATA_KEYS)
        original_keys = ['rpm', 'apps', 'coolant', 'fuelLevel', 'gearAuto', 'brakeSwitch',
                         'sportSwitch', 'espIntervention', 'espAbsIntervention', 'mil',
                         'lowOilPressure', 'tpmsFault', 'shiftLight1', 'shiftLight2',
                         'shiftLight3', 'espSystemState', 'espAbsErrorState',
                         'espAsrErrorState', 'espErrorState', 'time', 'textMessage']
        self.all_data_keys.update(original_keys)
        self.log_header = ['Timestamp'] + sorted(list(self.all_data_keys)) # Define header for CSV

    def set_update_interval(self, interval: float):
        """Sets the target interval for completing a full cycle of OBD/Mode22 requests."""
        # Ensure a minimum practical interval for the full request cycle
        self.request_interval = max(0.05, interval) # Set a minimum floor like 50ms
        self._log_func(f"Live data request interval set to {self.request_interval:.3f}s")

    def clear_log_buffer(self):
        """Clears the internal buffer used for CSV logging."""
        self.log_data_buffer = []

    def start(self) -> bool:
        """Starts the live dashboard processing and request loop."""
        if not self.can_comm or not self.can_comm.is_connected:
            self._log_func("Error: Cannot start dashboard, CAN not connected.")
            return False
        if self.running:
            self._log_func("Dashboard already running.")
            return True # Or False depending on desired behavior

        self._log_func("Starting live dashboard...")
        self._stop_event.clear()
        self.clear_log_buffer() # Clear buffer on start
        self.running = True

        # Initialize GUI with placeholders
        initial_data = {key: "..." for key in self.all_data_keys}
        self.live_data.update(initial_data)
        if callable(self.update_callback):
             try:
                 self.update_callback(initial_data)
             except Exception as cb_e:
                 self._log_func(f"Error during initial dashboard update callback: {cb_e}")

        # Start the request loop thread only if there are PIDs/DIDs to request
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
        """Stops the dashboard processing and the request loop thread."""
        if not self.running:
            return
        self._log_func("Stopping live dashboard processing...")
        self._stop_event.set() # Signal the request thread to stop

        if self.request_thread and self.request_thread.is_alive():
            self._log_func("Waiting for request thread to stop...")
            # Wait slightly longer than the request interval to ensure it can finish a cycle
            wait_time = (self.request_interval if self.request_interval > 0 else 1.0) + 0.5
            self.request_thread.join(timeout=wait_time)
            if self.request_thread.is_alive():
                self._log_func("Warning: Dashboard request thread did not stop cleanly.")
            else:
                self._log_func("Request thread stopped.")
        self.request_thread = None
        self.running = False
        # Note: CSV saving is triggered by the GUI's stop action now.
        self._log_func("Live dashboard stopped.")


    def save_log_to_csv(self) -> Optional[str]:
        """Saves the buffered log data to a uniquely named CSV file."""
        if not self.log_data_buffer:
            self._log_func("Log buffer is empty, nothing to save.")
            return None

        base_filename = "livedata_log"
        extension = ".csv"
        counter = 1
        filename = f"{base_filename}_{counter}{extension}"

        # Find the next available filename to avoid overwriting
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
            return filename
        except IOError as e:
            self._log_func(f"Error saving log file '{filename}': {e}")
        except Exception as e:
            self._log_func(f"Unexpected error saving CSV log: {e}")
            self._log_func(traceback.format_exc())
        return None

    def _request_loop(self):
        """Internal thread function to periodically request OBD Mode 01 and Mode 22 data."""
        self._log_func("Request loop initiated.")
        all_requests = []
        # Build the list of requests (Mode 01 and Mode 22)
        for key, pid in OBD_MODE_01_PIDS_TO_REQUEST.items():
             all_requests.append({'mode': 0x01, 'pid': pid, 'key': f"obd_{key}"}) # Key for logging/debug

        requested_dids = set()
        for key, did in MODE_22_PIDS_TO_REQUEST.items():
            if did not in requested_dids:
                all_requests.append({'mode': 0x22, 'did': did, 'key': f"m22_{did}"}) # Key for logging/debug
                requested_dids.add(did)

        if not all_requests:
            self._log_func("Request loop: No OBD/Mode22 PIDs configured. Thread exiting.")
            return

        self._log_func(f"Request loop will cycle through {len(all_requests)} requests with target interval {self.request_interval:.3f}s.")

        while not self._stop_event.is_set():
            cycle_start_time = time.monotonic()

            if not self.can_comm or not self.can_comm.is_connected:
                self._log_func("Request loop: CAN disconnected, pausing.")
                # Use wait with the interval to avoid busy-looping when disconnected
                self._stop_event.wait(self.request_interval if self.request_interval > 0 else 1.0)
                continue

            # --- Send all requests in this cycle ---
            for request_item in all_requests:
                if self._stop_event.is_set(): break # Exit if stopped during requests

                send_success = False
                # Use a short timeout for individual send_command calls within the loop
                # This waits for the *response* to this specific request
                individual_timeout = 0.2 # 200ms timeout for a single request/response

                if request_item['mode'] == 0x01:
                    pid = request_item['pid']
                    req_data = [0x02, 0x01, pid] # Standard OBD Mode 01 request format
                    send_success, _ = self.can_comm.send_command(
                        f"obd_req_{pid:02X}", req_id=UDS_REQUEST_ID, data=req_data,
                        timeout=individual_timeout, # Wait for this specific response
                        expected_response_service_id=0x41 # Positive response for Mode 01
                    )
                elif request_item['mode'] == 0x22:
                    did_str = request_item['did']
                    try:
                        did_hi = int(did_str[0:2], 16)
                        did_lo = int(did_str[2:4], 16)
                        req_data = [0x03, 0x22, did_hi, did_lo] # Standard Mode 22 request format
                        send_success, _ = self.can_comm.send_command(
                            f"m22_req_{did_str}", req_id=UDS_REQUEST_ID, data=req_data,
                            timeout=individual_timeout, # Wait for this specific response
                            expected_response_service_id=0x62 # Positive response for Mode 22
                        )
                    except ValueError:
                        self._log_func(f"Error: Invalid DID format '{did_str}'")
                    except Exception as e:
                         self._log_func(f"Error preparing Mode 22 req for {did_str}: {e}")

                # Optional small delay between *sending* requests if needed
                # Can help prevent bus congestion on very fast intervals
                # Adjust this value if needed, 0.01 = 10ms delay
                intersend_delay = 0.005 # 5ms delay between sends
                if intersend_delay > 0:
                    self._stop_event.wait(intersend_delay)

                # Log if send/response failed (optional, can be verbose)
                # if not send_success:
                #    self._log_func(f"Warning: Failed to send/get response for request: {request_item}")

            if self._stop_event.is_set(): break # Exit loop if stop signal received after last request

            # --- Calculate sleep time AFTER sending all requests for the cycle ---
            cycle_elapsed = time.monotonic() - cycle_start_time
            # Calculate remaining time to meet the target interval
            sleep_duration = max(0.01, self.request_interval - cycle_elapsed) # Ensure minimum 10ms sleep

            # Wait for the remainder of the interval before starting the next cycle
            self._stop_event.wait(sleep_duration)

        self._log_func("Request loop finished.")


    def _should_update(self, can_id: int) -> bool:
        """Throttles updates for frequently broadcast messages."""
        if can_id not in BROADCAST_LIVE_DATA_IDS:
            return True # Process non-broadcast or unknown IDs immediately
        now = time.monotonic()
        last_time = self._last_update_time.get(can_id, 0)
        if (now - last_time) >= self._broadcast_update_interval:
            self._last_update_time[can_id] = now
            return True
        return False

    def process_message(self, msg: can.Message):
        """Processes incoming CAN messages filtered by the notifier."""
        if not self.running: return
        arbitration_id = msg.arbitration_id
        data_bytes = bytes(msg.data) if hasattr(msg, 'data') and msg.data is not None else b''

        # 1. Handle Broadcast Messages (subject to throttling)
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
                        # self._log_func(traceback.format_exc()) # More detailed log if needed

        # 2. Handle Diagnostic Responses (Mode 01 / Mode 22)
        elif arbitration_id == UDS_REQUEST_ID + 8: # Check for 0x7E8
             try:
                 sid_index = -1; response_sid = 0; payload = b''
                 # Basic ISO-TP SF/FF check to find SID and payload (ignoring complex multi-frame assembly here as responses are expected to be short)
                 if len(data_bytes) >= 2 and (data_bytes[0] & 0xF0) == PCI_TYPE_SF << 4: # Check for SF PCI type
                     length = data_bytes[0] & 0x0F
                     if length != 0 and len(data_bytes) >= 1 + length: # Standard SF
                         sid_index = 1
                         payload = data_bytes[sid_index+1 : sid_index+1+length-1]
                     elif length == 0 and len(data_bytes) >= 3: # SF with length escape
                         sid_index = 2
                         payload = data_bytes[sid_index+1:] # Assume rest is payload
                 elif len(data_bytes) >= 3 and (data_bytes[0] & 0xF0) == PCI_TYPE_FF << 4: # Check for FF PCI type
                     sid_index = 2
                     payload = data_bytes[sid_index+1:] # Assume rest is payload

                 if sid_index != -1 and len(data_bytes) > sid_index:
                     response_sid = data_bytes[sid_index]
                     updates = {}
                     if response_sid == 0x41: # Mode 01 Response
                         updates = self._parse_obd_mode01_response(payload)
                     elif response_sid == 0x62: # Mode 22 Response
                         updates = self._parse_mode22_response(payload)
                     # Only send if updates were actually generated
                     if updates:
                         self._send_updates(updates)
                 # else: # Optional: Log if frame doesn't look like SF/FF response
                 #    self._log_func(f"Ignoring non-SF/FF frame on 0x7E8: {data_bytes.hex()}")

             except Exception as e:
                 self._log_func(f"Error parsing diagnostic response ID {arbitration_id:03X}: {type(e).__name__} - {e}")
                 # self._log_func(traceback.format_exc()) # More detailed log if needed

    def _send_updates(self, updates: Dict[str, Any]):
        """Updates internal state, logs a snapshot, and sends changes to the GUI."""
        changed_data_for_gui = {}
        # Create log entry *before* updating internal state to capture snapshot
        # Use None as default for missing keys in the log
        current_log_entry = {
            'Timestamp': datetime.now().isoformat(sep=' ', timespec='milliseconds')
        }
        current_log_entry.update({key: self.live_data.get(key, None) for key in self.log_header if key != 'Timestamp'})


        # Update internal state and identify changes for GUI
        for key, value in updates.items():
            if key in self.all_data_keys:
                # Check for actual change before marking for GUI update
                if self.live_data.get(key) != value:
                    changed_data_for_gui[key] = value
                # Update internal state regardless of change
                self.live_data[key] = value
                # Update the log entry with the new value
                current_log_entry[key] = value
            # else: # Optional: Log if an update key isn't in all_data_keys
            #    self._log_func(f"Warning: Received update for unknown key '{key}'")


        # Add the potentially updated snapshot to the buffer
        self.log_data_buffer.append(current_log_entry)

        # Send only changed data to the GUI callback
        if changed_data_for_gui:
            if callable(self.update_callback):
                try:
                    self.update_callback(changed_data_for_gui)
                except Exception as cb_e:
                     self._log_func(f"Error in dashboard update callback: {cb_e}")
            # else: # Warning if callback isn't callable (shouldn't happen normally)
            #      self._log_func("Warning: Live dashboard update_callback is not callable.")


    # --- OBD Mode 01 Parser ---
    def _parse_obd_mode01_response(self, payload: bytes) -> Dict[str, Any]:
        """Parses the data portion of an OBD Mode 01 response."""
        updates = {}
        if len(payload) < 1: return updates # Need at least PID

        pid = payload[0]
        pid_data = payload[1:]
        # self._log_func(f"Parsing OBD Mode 01 PID {pid:02X} Response: {payload.hex()}") # Verbose

        try:
            # Note: Calculations match standard OBD formulas
            if pid == 0x06 and len(pid_data) >= 1: updates['stftB1'] = (pid_data[0] - 128) * 100.0 / 128.0
            elif pid == 0x07 and len(pid_data) >= 1: updates['ltftB1'] = (pid_data[0] - 128) * 100.0 / 128.0
            elif pid == 0x08 and len(pid_data) >= 1: updates['stftB2'] = (pid_data[0] - 128) * 100.0 / 128.0
            elif pid == 0x09 and len(pid_data) >= 1: updates['ltftB2'] = (pid_data[0] - 128) * 100.0 / 128.0
            elif pid == 0x0E and len(pid_data) >= 1: updates['timingAdv'] = (pid_data[0] / 2.0) - 64.0
            elif pid == 0x0F and len(pid_data) >= 1: updates['iat'] = float(pid_data[0] - 40)
            elif pid == 0x10 and len(pid_data) >= 2: updates['maf'] = ((pid_data[0] * 256.0) + pid_data[1]) / 100.0
            elif pid == 0x11 and len(pid_data) >= 1: updates['throttlePos'] = pid_data[0] * 100.0 / 255.0
            elif pid == 0x24 and len(pid_data) >= 4: # Lambda B1S1 Equiv Ratio
                # Formula: (A*256 + B) / 32768 * 2
                ratio = ((pid_data[0] * 256.0) + pid_data[1]) / 32768.0 * 2.0
                updates['lambdaB1'] = ratio # Store calculated Lambda value
            elif pid == 0x26 and len(pid_data) >= 4: # Lambda B2S1 Equiv Ratio
                ratio = ((pid_data[0] * 256.0) + pid_data[1]) / 32768.0 * 2.0
                updates['lambdaB2'] = ratio
            elif pid == 0x46 and len(pid_data) >= 1: updates['aat'] = float(pid_data[0] - 40)
            # else: # Optional: Log unhandled PIDs if needed
            #    self._log_func(f"Received unhandled OBD PID {pid:02X}")

        except IndexError: self._log_func(f"Index error parsing OBD PID {pid:02X} payload {payload.hex()}")
        except Exception as e: self._log_func(f"Error parsing OBD PID {pid:02X}: {e}")
        return updates

    # --- UDS Mode 22 Parser ---
    def _parse_mode22_response(self, payload: bytes) -> Dict[str, Any]:
        """Parses the data portion of a UDS Mode 22 response."""
        updates = {}
        if len(payload) < 2: return updates # Need DID High and Low bytes

        did_hi = payload[0]
        did_lo = payload[1]
        did_str = f"{did_hi:02X}{did_lo:02X}".upper()
        did_data = payload[2:]

        scaling_info = MODE_22_SCALING.get(did_str)
        # self._log_func(f"Parsing Mode 22 DID {did_str} Response: {payload.hex()}") # Verbose

        try:
            # --- Special Handling for Multi-Value DIDs ---
            if did_str == '0231': # Knock Retard Cyl 1-4
                if len(did_data) >= 1: updates['knockCyl1'] = did_data[0] * 0.25
                if len(did_data) >= 2: updates['knockCyl2'] = did_data[1] * 0.25
                if len(did_data) >= 3: updates['knockCyl3'] = did_data[2] * 0.25
                if len(did_data) >= 4: updates['knockCyl4'] = did_data[3] * 0.25
                # self._log_func(f"  Knock Retard (0231): {updates}")
            elif did_str == '0256': # Knock Retard Cyl 5-6
                if len(did_data) >= 1: updates['knockCyl5'] = did_data[0] * 0.25
                if len(did_data) >= 2: updates['knockCyl6'] = did_data[1] * 0.25
                # self._log_func(f"  Knock Retard (0256): {updates}")

            # --- Generic Handling using Scaling Info ---
            elif scaling_info:
                # Find *all* keys that map to this DID (excluding the special knock ones handled above)
                keys_for_this_did = [k for k, req_did in MODE_22_PIDS_TO_REQUEST.items() if req_did == did_str and 'knockCyl' not in k]

                if keys_for_this_did:
                    pos = scaling_info['pos']
                    size = scaling_info['size']
                    if len(did_data) >= pos + size:
                        raw_bytes = did_data[pos : pos + size]
                        raw_value = int.from_bytes(raw_bytes, byteorder='big', signed=scaling_info['signed'])
                        scaled_value = (raw_value * scaling_info['scale']) + scaling_info['offset']
                        # Apply update to all keys associated with this DID
                        for key_to_update in keys_for_this_did:
                            updates[key_to_update] = scaled_value
                        # self._log_func(f"  Parsed DID {did_str} ({scaling_info['text']}) for keys '{keys_for_this_did}': {scaled_value}")
                    else:
                        self._log_func(f"Warning: Insufficient data length for DID {did_str}. Got {len(did_data)}, need {pos+size}")
            # else: # Optional: Log unhandled/unscaled DIDs
            #    self._log_func(f"Received unhandled/unscaled Mode 22 DID {did_str}")

        except IndexError:
            self._log_func(f"Index error parsing Mode 22 DID {did_str} with payload {payload.hex()}")
        except Exception as e:
            self._log_func(f"Error parsing Mode 22 DID {did_str}: {e}")
            # self._log_func(traceback.format_exc()) # More detail if needed

        return updates


    # --- Original Broadcast Parsers (Unchanged) ---
    def parse_esp_abs(self, data: bytes) -> Dict[str, Any]:
        updates = {}
        if len(data) >= 2:
            try:
                updates['espAbsErrorState'] = (data[0] >> 0) & 1; updates['espAbsIntervention'] = (data[0] >> 1) & 1
                updates['espAsrErrorState'] = (data[0] >> 2) & 1; updates['espAsrIntervention'] = (data[0] >> 3) & 1 # ASR intervention not used in display?
                # updates['espAsrLamp'] = (data[0] >> 4) & 1; # Lamp status not used directly
                updates['espErrorState'] = (data[0] >> 5) & 1; updates['espIntervention'] = (data[0] >> 6) & 1
                updates['espSystemState'] = data[1] & 0b11 # 0=Off, 1=On, 2=Fail, 3=Init
                # updates['brakeLamp'] = (data[1] >> 2) & 1; # Handled by 0x114
                # updates['sportLamp'] = (data[1] >> 3) & 1; # Handled by 0x114
            except IndexError: return {}
        return updates

    def parse_ecu_114(self, data: bytes) -> Dict[str, Any]:
        updates = {}
        if len(data) >= 6:
            try:
                rpm_raw = (data[1] << 8) + data[0]; updates['rpm'] = int(round(rpm_raw / 4.0, 0)) # Ensure int
                updates['apps'] = round(data[2] / 2.55, 1) # Pedal Position %
                # data[3] is Engine Load ?
                # data[4] bits: 0-5?, 6=ESP/ASR OFF lamp, 7=Sport Mode Active Lamp
                updates['sportSwitch'] = (data[4] >> 7) & 1 # Directly map sport lamp state
                # data[5] bits: 0=Brake Sw 1?, 1=Brake Sw 2? 2=Clutch Sw?, 3=Cruise?, 4=?, 5=?, 6=Start Signal?, 7=?
                updates['brakeSwitch'] = data[5] & 0b11 # Use combined brake status
            except IndexError: return {}
        return updates

    def parse_tcu_202(self, data: bytes) -> Dict[str, Any]:
        updates = {}
        if len(data) >= 1:
            gear_val = data[0] & 0b1111 # Lower 4 bits represent gear
            if gear_val == 0: gear_str = "P"
            elif gear_val == 1: gear_str = "R"
            elif gear_val == 2: gear_str = "N"
            elif 3 <= gear_val <= 8: gear_str = str(gear_val - 2) # 3=1st, 4=2nd ... 8=6th
            # Values 9-15 might be intermediate/shifting or unused states
            else: gear_str = "?" # Or perhaps "Shift"
            updates['gearAuto'] = gear_str
        return updates

    def parse_cluster_400(self, data: bytes) -> Dict[str, Any]:
        updates = {}
        if len(data) >= 7:
            try:
                # data[0-3] - Speedo/Tacho?
                updates['fuelLevel'] = round(data[4] / 2.55, 1) # Fuel Level %
                # Coolant temp uses a lookup table or complex formula typically, this is an approximation
                # Using a known formula: ((data[5]/255*1024)/1024*5-0.25)/0.028 + 1.5 ?? -> too complex
                # Simple linear scale - adjust offset/scale based on observation
                coolant_raw = data[5]
                updates['coolant'] = round((coolant_raw / 1.6) - 40, 1) # Approximate scale

                # Status Lamps Byte 1
                # updates['usa'] = (data[6] >> 0) & 1 # USA market indicator?
                updates['tpmsFault'] = (data[6] >> 1) & 1 # TPMS warning lamp
                # updates['unknown_lamp_6_2'] = (data[6] >> 2) & 1
                updates['lowOilPressure'] = (data[6] >> 3) & 1 # Oil pressure warning lamp
                updates['mil'] = (data[6] >> 4) & 1 # Malfunction Indicator Lamp (Check Engine)
                updates['shiftLight3'] = (data[6] >> 5) & 1 # Highest shift light
                updates['shiftLight2'] = (data[6] >> 6) & 1 # Middle shift light
                updates['shiftLight1'] = (data[6] >> 7) & 1 # Lowest shift light

                # Status Lamps Byte 2 (if present)
                if len(data) >= 8:
                    # updates['rearFogBulbCheck'] = (data[7] >> 2) & 1
                    # updates['coolantHot'] = (data[7] >> 3) & 1 # High coolant temp lamp?
                    # updates['spanner'] = (data[7] >> 7) & 1 # Service required lamp?
                    pass # Not decoding byte 7 lamps currently
            except IndexError: return {}
        return updates

    def parse_cluster_text(self, data: bytes) -> Dict[str, Any]:
        """Parses the text message broadcast from the cluster."""
        updates = {}
        if len(data) >= 2:
            try:
                # Attempt to decode ASCII, ignore errors, remove nulls, strip whitespace
                message = data[1:].decode('ascii', errors='ignore').replace('\x00','').strip()
                # Only send update if message content actually changes
                if self.live_data.get('textMessage') != message:
                    updates['textMessage'] = message
            except Exception:
                # If decoding fails, maybe send raw hex or an error message
                pass # Silently ignore for now
        return updates

    def parse_time_date(self, data: bytes) -> Dict[str, Any]:
        """Parses the time and date broadcast."""
        updates = {}
        if len(data) >= 7: # Need at least seconds to year_offset
            try:
                seconds = data[0]; minutes = data[1]; hours = data[2]
                day = data[3]; month = data[4]; year_offset = data[6] # Byte 5 is often day_of_week

                # Determine year (handle potential 2-byte year)
                if year_offset < 100: # Assume offset from 2000
                    year = 2000 + year_offset
                else: # Seems unlikely based on standard CAN, but handle just in case
                     # If year_offset > 99 maybe it indicates full year in byte 6+7? Unlikely.
                     # Assume it's just an offset >= 100 for now, might be invalid data.
                     year = 2000 + year_offset # This will likely result in an invalid year > 2099

                # Basic validation
                if not (0 <= seconds <= 59 and 0 <= minutes <= 59 and 0 <= hours <= 23 and
                        1 <= day <= 31 and 1 <= month <= 12 and 2000 <= year <= 2099):
                    raise ValueError("Date/Time component out of valid range")

                # Format consistently
                time_str = f"{year:04d}-{month:02d}-{day:02d} {hours:02d}:{minutes:02d}:{seconds:02d}"

                # Only update if the time string has changed
                if self.live_data.get('time') != time_str:
                    updates['time'] = time_str

            except (IndexError, ValueError):
                 # If parsing fails, set to an error state if not already set
                 if self.live_data.get('time') != "Date/Time Error":
                     updates['time'] = "Date/Time Error"
            except Exception as e:
                self._log_func(f"Unexpected error parsing time/date: {e}")
                if self.live_data.get('time') != "Date/Time Error":
                     updates['time'] = "Date/Time Error"
        return updates