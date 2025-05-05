# can_communication.py

# Handles communication with the CANBUS

import can
import time
import threading
import queue
import logging
import traceback
from typing import Optional, List, Tuple, Dict, Any, Set, Union
import enum

# ISO-TP Frame Types / PCI (Protocol Control Information) Types
PCI_TYPE_SF = 0x0  # Single Frame
PCI_TYPE_FF = 0x1  # First Frame
PCI_TYPE_CF = 0x2  # Consecutive Frame
PCI_TYPE_FC = 0x3  # Flow Control

# Flow Control Status Types (Used in FC frames)
FC_STATUS_CTS = 0x0 # Clear To Send
FC_STATUS_WT  = 0x1 # Wait
FC_STATUS_OVFLW = 0x2 # Overflow

# Standard UDS Arbitration IDs
UDS_REQUEST_ID: int = 0x7E0; UDS_RESPONSE_ID: int = 0x7E8
ABS_REQUEST_ID: int = 0x6F4; ABS_RESPONSE_ID: int = 0x6F5 # KWP ID
TCU_REQUEST_ID: int = 0x7E1; TCU_RESPONSE_ID: int = 0x7E9
RELEVANT_RESPONSE_IDS: Set[int] = {UDS_RESPONSE_ID, ABS_RESPONSE_ID, TCU_RESPONSE_ID}
# Define which IDs strictly use ISO-TP multi-frame logic
UDS_RESPONSE_IDS_FOR_ISOTP: Set[int] = {UDS_RESPONSE_ID, TCU_RESPONSE_ID}

# Command Mapping - Inc. Faults, KWP, OBD
COMMANDS: Dict[str, Optional[Tuple[int, List[int]]]] = {
    'getVin': (UDS_REQUEST_ID, [0x02, 0x09, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00]),
    'getEngineFaultsNormal': (UDS_REQUEST_ID, [0x02, 0x19, 0x02, 0x09, 0x00, 0x00, 0x00, 0x00]),
    'getEngineFaultsSpecial': (UDS_REQUEST_ID, [0x02, 0x19, 0x01, 0xFF, 0x00, 0x00, 0x00, 0x00]),
    'getEngineFaultsNormalPending': (UDS_REQUEST_ID, [0x02, 0x19, 0x02, 0x08, 0x00, 0x00, 0x00, 0x00]), # Use $19 02 with pending mask (e.g., 0x08)
    'getGearboxFaultsNormal': (TCU_REQUEST_ID, [0x02, 0x19, 0x02, 0xFF, 0x00, 0x00, 0x00, 0x00]),
    'getGearboxFaultsSpecial': (TCU_REQUEST_ID, [0x02, 0x19, 0x01, 0xFF, 0x00, 0x00, 0x00, 0x00]),
    'clearEngineFaultsNormal': (UDS_REQUEST_ID, [0x04, 0x14, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00]),
    'clearEngineFaultsSpecial': (UDS_REQUEST_ID, [0x04, 0x14, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00]),
    'clearGearboxFaultsNormal': (TCU_REQUEST_ID, [0x04, 0x14, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00]),
    'clearGearboxFaultsSpecial': (TCU_REQUEST_ID, [0x04, 0x14, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00]),
    'getObdConfirmedFaults': (UDS_REQUEST_ID, [0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), # OBD Mode $03
    'getObdPendingFaults': (UDS_REQUEST_ID, [0x01, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),   # OBD Mode $07
    # KWP Commands referenced directly by 's' name prefix in diagnostics.py
    's06F4021089': (ABS_REQUEST_ID, [0x02, 0x10, 0x89, 0x00, 0x00, 0x00, 0x00, 0x00]), # Session Standby
    's06F4031300FF': (ABS_REQUEST_ID, [0x03, 0x13, 0x00, 0xFF]), # KWP Read DTC (Service $13, Type $00, Group $FF=All) - Preferred
    's06F4041800FF00': (ABS_REQUEST_ID, [0x04, 0x18, 0x00, 0xFF, 0x00]), # KWP Read DTC by Status (Service $18, Type $00, Status $FF=All) - Alternative
    's06F40314FF00': (ABS_REQUEST_ID, [0x03, 0x14, 0xFF, 0x00]), # KWP Clear DTC? (Service $14, Group $FF=All)
    'monitorAllStart': None, 'monitorAllStop': None,
    'enableFlowControl': None, 'disableFlowControl': None,
    # --- OBD Mode 01 Commands ---
    # Format: [Length (incl. Mode & PID), Mode (01), PID] + Padding
    # Fuel Trims
    'getSTFTB1': (UDS_REQUEST_ID, [0x02, 0x01, 0x06, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]),
    'getLTFTB1': (UDS_REQUEST_ID, [0x02, 0x01, 0x07, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]),
    'getSTFTB2': (UDS_REQUEST_ID, [0x02, 0x01, 0x08, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]),
    'getLTFTB2': (UDS_REQUEST_ID, [0x02, 0x01, 0x09, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]),
    # Timing Advance
    'getTimingAdv': (UDS_REQUEST_ID, [0x02, 0x01, 0x0E, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]),
    # IAT
    'getIAT': (UDS_REQUEST_ID, [0x02, 0x01, 0x0F, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]),
    # MAF
    'getMAF': (UDS_REQUEST_ID, [0x02, 0x01, 0x10, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]),
    # Throttle Position
    'getThrottlePos': (UDS_REQUEST_ID, [0x02, 0x01, 0x11, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]),
    # Lambda / O2 Sensors (Equivalence Ratio - often Bank 1 Sensor 1 and Bank 2 Sensor 1)
    'getLambdaB1S1': (UDS_REQUEST_ID, [0x02, 0x01, 0x24, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]),
    'getLambdaB2S1': (UDS_REQUEST_ID, [0x02, 0x01, 0x26, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]),
    # AAT
    'getAAT': (UDS_REQUEST_ID, [0x02, 0x01, 0x46, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]),
}

# Diagnostic Session Constants
DEFAULT_SESSION = 0x01
EXTENDED_SESSION = 0x03
STANDBY_SESSION = 0x89 # Example specific session for ABS based on s command

class ISOTPState(enum.Enum):
    IDLE = 0
    WAIT_CF = 1
    WAIT_FC = 2

# --- HELPER FUNCTION ---
def decode_nrc(nrc: int) -> str:
    """Decodes common Negative Response Codes."""
    nrc_map = {
        0x10: "General Reject", 0x11: "Service Not Supported", 0x12: "SubFunction Not Supported",
        0x13: "Incorrect Message Length Or Invalid Format", 0x14: "Response Too Long",
        0x21: "Busy Repeat Request", 0x22: "Conditions Not Correct", 0x24: "Request Sequence Error",
        0x31: "Request Out Of Range", 0x33: "Security Access Denied", 0x35: "Invalid Key",
        0x36: "Exceeded Number Of Attempts", 0x37: "Required Time Delay Not Expired",
        0x78: "Request Correctly Received - Response Pending", 0x7E: "SubFunction Not Supported In Active Session",
        0x7F: "Service Not Supported In Active Session",
        # Add more NRC codes here if needed
    }
    return nrc_map.get(nrc, f"Unknown NRC {nrc:02X}")
# --- END HELPER FUNCTION ---

class ILiveDataProcessor:
    TARGET_IDS: Set[int] = set()
    def process_message(self, msg: can.Message): raise NotImplementedError

class CanCommunication:
    def __init__(self, channel: Optional[str], gui_queue: queue.Queue, interface: str = 'usb2can', bitrate: int = 500000):
        self.channel: Optional[str] = channel; self.interface: str = interface; self.bitrate: int = bitrate
        self.gui_queue: queue.Queue = gui_queue; self.bus: Optional[can.BusABC] = None
        self.is_connected: bool = False; self.reader_thread: Optional[threading.Thread] = None
        self.running: bool = False; self.rx_queue: queue.Queue = queue.Queue(maxsize=500)
        self.response_queue: queue.Queue = queue.Queue()
        self.notifier: Optional[can.Notifier] = None
        self.live_dashboard_processor: Optional[ILiveDataProcessor] = None
        self._isotp_state: ISOTPState = ISOTPState.IDLE
        self._isotp_target_id: Optional[int] = None
        self._isotp_buffer: List[int] = []
        self._isotp_expected_len: int = 0
        self._isotp_frame_index: int = 0
        self._isotp_flow_control_id: Optional[int] = None
        self._isotp_block_size: int = 0
        self._isotp_stmin: float = 0.0
        self._isotp_frames_since_fc: int = 0
        self._isotp_lock = threading.Lock()
        self.debug_log_all_enabled: bool = False
        self._log_raw_diag_active: bool = False
        self._log_raw_diag_until: float = 0.0
        self.RAW_DIAG_LOG_DURATION: float = 6.0

    # _log, connect, disconnect, _on_message_received_callback unchanged
    def _log(self, message: str):
        try: self.gui_queue.put(("log", str(message)))
        except Exception as e: print(f"LOG (queue error: {e}): {message}")

    def connect(self) -> bool:
        if self.is_connected: self._log("Already connected."); return True
        try:
            self._log(f"Initializing CAN bus: interface={self.interface}, channel='{self.channel}', bitrate={self.bitrate}")
            bus_kwargs = {'channel': self.channel, 'interface': self.interface, 'bitrate': self.bitrate}
            try:
                self.bus = can.interface.Bus(**bus_kwargs, receive_own_messages=False)
                self._log("Set receive_own_messages=False")
            except TypeError:
                self._log("Warning: Interface might not support receive_own_messages setting.")
                if 'receive_own_messages' in bus_kwargs: del bus_kwargs['receive_own_messages'] # Remove unsupported kwarg
                self.bus = can.interface.Bus(**bus_kwargs) # Try without it

            self.notifier = can.Notifier(self.bus, [self._on_message_received_callback], timeout=0.1)
            self.running = True
            self.reader_thread = threading.Thread(target=self._read_loop, daemon=True, name="CANReadThread"); self.reader_thread.start()
            self.is_connected = True; self._log(f"Successfully connected via {self.interface} on '{self.channel}'"); return True
        except can.CanError as e: self._log(f"CAN Connection Error: {e}\nCheck drivers, DLL path, serial number/channel, and device connection.")
        except Exception as e: self._log(f"Connect Error: {type(e).__name__}: {e}\n{traceback.format_exc()}")
        self.is_connected = False
        if self.bus:
            try: self.bus.shutdown()
            except Exception as sd_e: self._log(f"Bus shutdown error on fail: {sd_e}")
        if self.notifier:
             try: self.notifier.stop()
             except Exception as ne: self._log(f"Notifier stop error on fail: {ne}")
        self.bus = None; self.notifier = None; return False

    def disconnect(self):
        if not self.is_connected: self._log("Not connected."); return
        self._log("Disconnecting from CAN bus..."); self.running = False
        if self.notifier:
            try: self.notifier.stop(timeout=0.5); self._log("Notifier stopped.")
            except Exception as e: self._log(f"Error stopping notifier: {e}")
            finally: self.notifier = None
        if self.reader_thread and self.reader_thread.is_alive():
            self._log("Waiting for reader thread..."); self.reader_thread.join(timeout=0.5)
            if self.reader_thread.is_alive(): self._log("Warning: Reader thread did not exit cleanly.")
            else: self._log("Reader thread stopped.")
            self.reader_thread = None
        if self.bus:
            try: self._log("Shutting down CAN bus..."); self.bus.shutdown(); self._log("CAN bus shut down.")
            except Exception as e: self._log(f"Error shutting down bus: {e}")
            finally: self.bus = None
        self.is_connected = False; self._log("Clearing queues...");
        while not self.rx_queue.empty():
             try: self.rx_queue.get_nowait()
             except queue.Empty: break
        while not self.response_queue.empty():
             try: self.response_queue.get_nowait()
             except queue.Empty: break
        with self._isotp_lock:
             self._reset_isotp_state()
        self._log("Disconnected.")

    def _on_message_received_callback(self, msg: can.Message):
        if self.running:
            try: self.rx_queue.put_nowait(msg)
            except queue.Full:
                if hasattr(self, '_last_q_full_log_time'):
                    now = time.monotonic()
                    if now - self._last_q_full_log_time > 5.0:
                        self._log("Warning: RX queue full.")
                        self._last_q_full_log_time = now
                else:
                    self._last_q_full_log_time = time.monotonic()
                    self._log("Warning: RX queue full.")
            except Exception as e:
                 if hasattr(self, '_last_rx_err_log_time'):
                     now = time.monotonic()
                     if now - self._last_rx_err_log_time > 10.0:
                          self._log(f"Error in RX callback: {e}")
                          self._last_rx_err_log_time = now
                 else:
                     self._last_rx_err_log_time = time.monotonic()
                     self._log(f"Error in RX callback: {e}")

    # --- Raw Logging Control ---
    def _activate_raw_diag_logging(self):
        """Activates raw diagnostic logging for a set duration."""
        self._log_raw_diag_active = True
        self._log_raw_diag_until = time.monotonic() + self.RAW_DIAG_LOG_DURATION
        self._log(f"[RAW_DIAG_RX] Logging enabled for {self.RAW_DIAG_LOG_DURATION}s")

    def _deactivate_raw_diag_logging(self):
        """Deactivates raw diagnostic logging."""
        if self._log_raw_diag_active:
            self._log_raw_diag_active = False
            self._log("[RAW_DIAG_RX] Logging disabled.")

    # --- Read Loop with Raw Logging ---
    def _read_loop(self):
        """Processes messages from the rx_queue."""
        self._log("CAN Read Loop started.")
        while self.running:
            try:
                msg = self.rx_queue.get(timeout=0.1) # Wait for message

                # --- Raw Diagnostic Logging Check ---
                if self._log_raw_diag_active:
                    now = time.monotonic()
                    if now < self._log_raw_diag_until:
                        # Log only relevant diagnostic response IDs raw
                        if msg.arbitration_id in RELEVANT_RESPONSE_IDS:
                           self._log(f"[RAW_DIAG_RX] ID={msg.arbitration_id:03X} DLC={msg.dlc} Data={msg.data.hex().upper()}")
                    else:
                        self._deactivate_raw_diag_logging()
                # --- End Raw Diagnostic Logging ---

                # --- Standard Message Routing ---
                is_diagnostic_response = msg.arbitration_id in RELEVANT_RESPONSE_IDS
                is_live_data = False
                processor = self.live_dashboard_processor
                if processor and hasattr(processor, 'TARGET_IDS'):
                     is_live_data = msg.arbitration_id in processor.TARGET_IDS

                if is_live_data and processor:
                    try:
                        if callable(getattr(processor, 'process_message', None)): processor.process_message(msg)
                        else: self._log(f"Error: Live processor missing method."); self.live_dashboard_processor = None
                    except Exception as live_e: self._log(f"Error processing live ID {msg.arbitration_id:X}: {live_e}")

                if is_diagnostic_response:
                     try: self._parse_incoming_message(msg) # Pass to parser
                     except Exception as parse_e: self._log(f"Error parsing response ID {msg.arbitration_id:X}: {parse_e}")

            except queue.Empty: continue # Normal timeout
            except Exception as e: self._log(f"Error in read loop: {e}"); time.sleep(0.1)
        self._log("CAN Read Loop stopped.")

    # --- Sending CAN Message ---
    def _send_can_message(self, arbitration_id: int, data: Any, is_extended: bool =False) -> bool:
        if not self.is_connected or not self.bus: self._log("Error: Cannot send, not connected."); return False
        try:
            if isinstance(data, str): data_bytes = bytes.fromhex(data)
            elif isinstance(data, (list, tuple)):
                 if any(b < 0 or b > 255 for b in data): raise ValueError("Data bytes must be 0-255")
                 data_bytes = bytes(data)
            elif isinstance(data, bytes): data_bytes = data
            else: self._log(f"Error: Invalid CAN data type: {type(data)}"); return False

            if len(data_bytes) > 8:
                 self._log(f"Error: CAN data length ({len(data_bytes)}) exceeds 8 bytes for standard frame. ID={arbitration_id:03X}")
                 return False

            if len(data_bytes) < 8:
                padded_data = data_bytes + bytes([0xAA] * (8 - len(data_bytes))) # Use a common padding byte like AA
            else:
                padded_data = data_bytes

            message = can.Message(
                arbitration_id=arbitration_id, data=padded_data,
                is_extended_id=is_extended, is_fd=False,
                dlc=len(data_bytes) # Set correct DLC if interface supports it
                )
            self.bus.send(message, timeout=0.2)
            # Log only the actual sent bytes, not padding
            self._log(f"Sent: ID={arbitration_id:03X} DLC={len(data_bytes)} Data={data_bytes.hex().upper()}")
            return True
        except ValueError as ve: self._log(f"Data Error sending CAN (ID: {arbitration_id:03X}): {ve}")
        except can.CanError as e: self._log(f"CAN Bus Error sending (ID: {arbitration_id:03X}): {e}")
        except Exception as e: self._log(f"Unexpected error sending CAN (ID: {arbitration_id:03X}): {e}")
        return False

    # --- send_command with corrected KWP handling in response loop ---
    def send_command(self, command_name: str, timeout: float = 3.0,
                     req_id: Optional[int] = None, data: Optional[Union[List[int], bytes]] = None,
                     is_extended: bool = False,
                     expected_response_service_id: Optional[int] = None) -> Tuple[bool, Optional[List[int]]]:
        """
        Sends a command and waits for a potentially multi-frame response.
        Args:
            command_name: Name of the command (from COMMANDS, 'pXXXX', or 'sXXXXXX...') or custom name for logging.
            timeout: Total time to wait for the complete response.
            req_id: CAN ID to send to (overrides command_name lookup).
            data: Data bytes/list to send (overrides command_name lookup).
            is_extended: Use extended CAN ID.
            expected_response_service_id: If provided, only accepts responses where the service ID byte matches this value.
        Returns:
            Tuple (success: bool, response_data: Optional[List[int]])
            response_data format from queue:
              - UDS SF: [pci_byte(incl.len), service_id, ...]
              - UDS MF: [ff_pci, len_low, service_id, ...] (assembled payload)
              - KWP: [service_id, ...] (payload starting with SID)
              - NRC: Contains the negative response code data structure specific to protocol.
        """
        if not self.is_connected: self._log(f"Error: Cannot send '{command_name}', not connected."); return False, None

        # --- Resolve Command ---
        resolved_req_id: Optional[int] = req_id
        resolved_data: Optional[Union[List[int], bytes]] = data
        resolved_is_extended: bool = is_extended
        request_service_id: Optional[int] = None

        if resolved_req_id is None or resolved_data is None:
            if command_name.startswith('p'):
                 try: did_hex = command_name[1:]; assert len(did_hex) == 4; did_int = int(did_hex, 16); resolved_req_id = UDS_REQUEST_ID; resolved_data = [0x03, 0x22, (did_int >> 8) & 0xFF, did_int & 0xFF]; request_service_id = 0x22
                 except (ValueError, AssertionError) as e: self._log(f"Error: Invalid perf cmd format '{command_name}': {e}"); return False, None
            elif command_name.startswith('s'):
                try: assert len(command_name) >= 7; raw_id_hex = command_name[1:5]; raw_data_hex = command_name[5:]; assert len(raw_data_hex) % 2 == 0; resolved_req_id = int(raw_id_hex, 16); resolved_data = bytes.fromhex(raw_data_hex); request_service_id = resolved_data[1] if len(resolved_data) > 1 else None
                except (ValueError, AssertionError, Exception) as e: self._log(f"Error parsing raw send cmd '{command_name}': {e}"); return False, None
            else:
                command_tuple = COMMANDS.get(command_name)
                if command_tuple is None:
                    if command_name in COMMANDS: self._log(f"Executing local action: {command_name}"); return True, None # E.g. flow control enable/disable
                    else: self._log(f"Error: Command '{command_name}' not recognized."); return False, None
                resolved_req_id, data_list = command_tuple; resolved_data = bytes(data_list); request_service_id = data_list[1] if len(data_list) > 1 else None

        if resolved_req_id is None or resolved_data is None: self._log(f"Internal Error: No CAN msg data for '{command_name}'."); return False, None

        # --- Prepare for Response ---
        while not self.response_queue.empty():
            try: stale_msg = self.response_queue.get_nowait(); self._log(f"Cleared stale msg from resp queue: {stale_msg}")
            except queue.Empty: break
        with self._isotp_lock:
            self._reset_isotp_state()
            if resolved_req_id in UDS_RESPONSE_IDS_FOR_ISOTP or resolved_req_id == UDS_REQUEST_ID:
                 self._isotp_target_id = resolved_req_id + 8 # Target the corresponding UDS response ID

        # --- Activate Raw Logging & Send Command ---
        self._activate_raw_diag_logging()
        if not self._send_can_message(resolved_req_id, resolved_data, resolved_is_extended):
            self._deactivate_raw_diag_logging(); return False, None

        # --- Wait for Response ---
        start_time = time.monotonic()
        response_received: Optional[List[int]] = None
        success_flag = False
        is_kwp_request = resolved_req_id == ABS_REQUEST_ID # Determine if this was a KWP request

        while True:
            current_time = time.monotonic()
            if current_time - start_time > timeout:
                self._log(f"Timeout ({timeout}s) waiting for response to {command_name} (ReqID: {resolved_req_id:X})")
                with self._isotp_lock: self._reset_isotp_state()
                success_flag = False; response_received = None
                break

            try:
                response_data = self.response_queue.get(block=True, timeout=0.1)

                # --- Determine Service ID Index based on protocol ---
                service_id_index = -1 # Index within response_data where SID is expected
                response_format_type = "Unknown"
                actual_service_id = None

                if not response_data:
                    self._log(f"Received empty response fragment. Continuing wait.")
                    continue

                if is_kwp_request:
                    # For KWP, assume SID is the *first* byte from the queue
                    # (because _parse_incoming_message now puts [SID, Payload...])
                    service_id_index = 0
                    response_format_type = "KWP"
                    if len(response_data) > service_id_index:
                        actual_service_id = response_data[service_id_index]
                    else:
                         self._log(f"Received invalid/short KWP response fragment: {response_data}. Continuing wait.")
                         continue
                else: # UDS/ISO-TP path
                    # Determine UDS SID index based on PCI byte
                    if not response_data: continue # Should not happen here, but check again
                    first_byte = response_data[0]
                    pci_type = (first_byte >> 4) & 0x0F

                    if pci_type == PCI_TYPE_FF: # UDS MF: [ff_pci, len_low, SID, ...]
                        if len(response_data) >= 3:
                            service_id_index = 2; response_format_type = "UDS_MF"
                    elif pci_type == PCI_TYPE_SF: # UDS SF: [pci_byte(incl.len), SID, ...]
                        if len(response_data) >= 2:
                             service_id_index = 1; response_format_type = "UDS_SF"
                    elif first_byte == 0x00 and len(response_data) >= 3: # UDS SF length escape [0x00, Len, SID, ...]
                        service_id_index = 2; response_format_type = "UDS_SF_ESC"

                    # Extract SID if index found
                    if service_id_index != -1:
                         actual_service_id = response_data[service_id_index]
                    else:
                         self._log(f"Received ambiguous/short UDS response: {response_data}. Continuing wait.")
                         continue # Cannot determine SID

                # --- Validate Response ---
                if actual_service_id is None: # Should not happen if checks above are correct
                     self._log(f"Could not determine actual_service_id for response: {response_data}. Format guess: {response_format_type}. Continuing wait.")
                     continue

                # Check for Negative Response (NRC = 0x7F)
                is_negative_response = False
                nrc = 0
                req_serv_echo = 0

                if is_kwp_request and actual_service_id == 0x7F:
                    # KWP NRC format assumed from queue: [0x7F, req_sid_echo, nrc, ...]
                    is_negative_response = True
                    req_serv_echo = response_data[1] if len(response_data) > 1 else 0
                    nrc = response_data[2] if len(response_data) > 2 else 0
                elif not is_kwp_request and actual_service_id == 0x7F:
                    # UDS NRC format depends on frame type, SID echo is SID + 1, NRC is SID + 2
                    is_negative_response = True
                    sid_echo_index = service_id_index + 1
                    nrc_index = service_id_index + 2
                    if len(response_data) > nrc_index:
                        req_serv_echo = response_data[sid_echo_index]
                        nrc = response_data[nrc_index]
                    else: # Cannot reliably extract NRC
                        self._log(f"Warning: Short UDS NRC response received: {response_data}")
                        req_serv_echo = request_service_id if request_service_id is not None else 0xFF # Guess
                        nrc = 0 # Unknown NRC

                if is_negative_response:
                    # Check if NRC is for the service we just sent
                    if request_service_id is None or req_serv_echo == request_service_id:
                         self._log(f"Received NRC: {nrc:02X} ({decode_nrc(nrc)}) for Service ${req_serv_echo:02X} (Command: {command_name}) Format: {response_format_type}")
                         with self._isotp_lock: self._reset_isotp_state()
                         success_flag = False; response_received = response_data # Keep NRC response data
                         break # Exit loop, NRC received for our command
                    else:
                         self._log(f"Ignoring late NRC: {nrc:02X} for Service ${req_serv_echo:02X} while waiting for Service ${request_service_id:02X} (Cmd: {command_name})")
                         continue # Ignore this NRC and continue waiting

                # Check for Positive Response Match
                if expected_response_service_id is not None:
                    if actual_service_id == expected_response_service_id:
                        # self._log(f"Received expected positive response (SID: {actual_service_id:02X}, Format: {response_format_type}) for {command_name}")
                        success_flag = True; response_received = response_data
                        break # Correct positive response received
                    else:
                        # Log the unexpected positive response
                        log_data_hex = bytes(response_data).hex().upper()
                        self._log(f"Ignoring mismatched positive response (Expected SID: {expected_response_service_id:02X}, Got SID: {actual_service_id:02X}, Format: {response_format_type}, Data: {log_data_hex}) while waiting for {command_name}")
                        continue # Ignore this response and continue waiting
                else: # Accept first positive response if no specific SID expected
                    # self._log(f"Received first positive response (SID: {actual_service_id:02X}, Format: {response_format_type}) for {command_name}")
                    success_flag = True; response_received = response_data
                    break # First positive response is acceptable

            except queue.Empty: continue # Normal timeout, loop again
            except Exception as e:
                self._log(f"Error processing response queue: {e}\n{traceback.format_exc()}")
                success_flag = False; response_received = None
                break # Exit loop on unexpected error

        self._deactivate_raw_diag_logging()
        return success_flag, response_received

    # [_send_flow_control unchanged]
    def _send_flow_control(self, flow_status: int = FC_STATUS_CTS, block_size: int = 0, st_min_ms: int = 0):
        if self._isotp_flow_control_id is None:
            self._log("Error: Cannot send FC, flow control target ID not set.")
            return
        # Determine destination ID for FC (usually request ID = response ID - 8)
        if 0x7E8 <= self._isotp_flow_control_id <= 0x7EF:
            fc_destination_id = self._isotp_flow_control_id - 8
        # Add other known response ranges if needed, e.g., 0x7E9 -> 0x7E1
        elif self._isotp_flow_control_id == TCU_RESPONSE_ID:
            fc_destination_id = TCU_REQUEST_ID
        else:
            # Avoid sending FC for non-standard or potentially KWP IDs unless explicitly handled
            self._log(f"Warn: Suppressing FC frame intended for non-standard response ID {self._isotp_flow_control_id:X}.")
            return

        # Double check we are not sending FC to a known KWP request ID
        if fc_destination_id == ABS_REQUEST_ID:
            self._log(f"Warn: Suppressing FC frame intended for KWP request ID {fc_destination_id:X}.")
            return

        st_min_bytes = 0x00
        if 0 <= st_min_ms <= 127: st_min_bytes = st_min_ms # 0-127 ms
        elif 0xF1 <= st_min_ms <= 0xF9: st_min_bytes = st_min_ms # 100-900 us
        else: self._log(f"Warn: STmin {st_min_ms}ms out of standard range, using 0ms.")

        fc_pci = (PCI_TYPE_FC << 4) | (flow_status & 0x0F)
        fc_data = [fc_pci, block_size & 0xFF, st_min_bytes]
        flow_status_str = {FC_STATUS_CTS: "CTS", FC_STATUS_WT: "WAIT", FC_STATUS_OVFLW: "OVFLW"}.get(flow_status, "?")
        self._log(f"Sending Flow Control ({flow_status_str}, BS={block_size}, STmin={st_min_ms}ms) to ID {fc_destination_id:03X}")
        self._send_can_message(fc_destination_id, fc_data)

    # --- ISO-TP Parsing Logic ---
    def _reset_isotp_state(self):
        # self._log("Resetting ISO-TP state") # Optional: for debugging
        if self._isotp_state != ISOTPState.IDLE: pass # Could log previous state if needed
        self._isotp_state = ISOTPState.IDLE
        self._isotp_target_id = None
        self._isotp_buffer = []
        self._isotp_expected_len = 0
        self._isotp_frame_index = 0
        self._isotp_flow_control_id = None
        self._isotp_block_size = 0
        self._isotp_stmin = 0.0
        self._isotp_frames_since_fc = 0

    # --- _parse_incoming_message with corrected KWP handling ---
    def _parse_incoming_message(self, msg: can.Message):
        """Parses incoming diagnostic messages, handling ISO-TP and basic KWP."""
        if not hasattr(msg, 'data') or not msg.data or msg.dlc == 0: return
        data_bytes = list(msg.data)
        arbitration_id = msg.arbitration_id

        try:
            # Handle non-UDS IDs (e.g., KWP on ABS_RESPONSE_ID) first
            if arbitration_id not in UDS_RESPONSE_IDS_FOR_ISOTP:
                 if arbitration_id == ABS_RESPONSE_ID:
                     # KWP responses: Put ONLY the payload starting from the SID byte
                     # e.g., Raw [02 50 89 ...] -> Queue [0x50, 0x89, ...]
                     if msg.dlc >= 2: # KWP response must have at least SID byte (after length/format byte)
                        payload_kwp = data_bytes[1:msg.dlc] # Get payload starting from byte 1 up to DLC
                        self.response_queue.put(payload_kwp)
                     # else: # Optional: log if KWP response too short
                     #    self._log(f"Warning: Received KWP message from {arbitration_id:X} too short (DLC={msg.dlc}).")
                 else:
                     pass # Ignore other unexpected diagnostic IDs
                 return # Stop processing for non-ISO-TP IDs

            # --- ISO-TP Logic for UDS IDs ---
            pci_byte = data_bytes[0]
            frame_type = (pci_byte >> 4) & 0x0F

            with self._isotp_lock:
                if self._isotp_state == ISOTPState.IDLE:
                    if frame_type == PCI_TYPE_SF:
                        self._handle_sf(arbitration_id, data_bytes, msg.dlc)
                    elif frame_type == PCI_TYPE_FF:
                        self._handle_ff(arbitration_id, data_bytes, msg.dlc)
                    elif frame_type == PCI_TYPE_CF:
                         self._log(f"Warn: Received unexpected CF from ID {arbitration_id:X} in IDLE state. Resetting.")
                         self._reset_isotp_state()
                    elif frame_type == PCI_TYPE_FC:
                         fs = pci_byte & 0x0F; flow_status_str = {0: "CTS", 1: "WAIT", 2: "OVFLW"}.get(fs, f"?({fs})"); self._log(f"Warn: Received unexpected FC ID {arbitration_id:X} in IDLE state. FS={flow_status_str}. Ign.")

                elif self._isotp_state == ISOTPState.WAIT_CF:
                    if arbitration_id != self._isotp_target_id:
                        # self._log(f"Debug: Ignoring message from {arbitration_id:X}, waiting for {self._isotp_target_id:X}")
                        return # Ignore messages from other IDs

                    if frame_type == PCI_TYPE_CF:
                        self._handle_cf(arbitration_id, data_bytes, msg.dlc)
                    elif frame_type == PCI_TYPE_FC:
                         # Should not happen if we are the receiver waiting for CF, sender sends FC
                         self._log(f"Warn: Received unexpected FC from {arbitration_id:X} while waiting for CF. Handling anyway.")
                         self._handle_fc(arbitration_id, data_bytes) # Handle it, might be a sender retry?
                    else: # SF or FF received while waiting for CF
                        self._log(f"Error: Expected CF from {arbitration_id:X}, got type {frame_type:X}. Resetting state.")
                        self._reset_isotp_state()
                        # Attempt to process the new frame if it's a start frame
                        if frame_type == PCI_TYPE_SF: self._handle_sf(arbitration_id, data_bytes, msg.dlc)
                        elif frame_type == PCI_TYPE_FF: self._handle_ff(arbitration_id, data_bytes, msg.dlc)
                # Note: ISOTPState.WAIT_FC is typically used when *sending* multi-frame,
                # not receiving, so no explicit handling here for incoming messages.

        except IndexError as e:
             self._log(f"Error parsing msg (IndexError): {e}, Data: {bytes(msg.data).hex()}, ID: {arbitration_id:X}")
             with self._isotp_lock: self._reset_isotp_state() # Reset ISO-TP state on error
        except Exception as e:
             self._log(f"Unexpected error parsing msg: {type(e).__name__}: {e}, Data: {bytes(msg.data).hex()}, ID: {arbitration_id:X}")
             with self._isotp_lock: self._reset_isotp_state() # Reset ISO-TP state on error

    # --- ISO-TP Frame Handlers (_handle_sf, _handle_ff, _handle_cf, _handle_fc) ---

    def _handle_sf(self, arbitration_id: int, data_bytes: List[int], dlc: int):
        """Handles an ISO-TP Single Frame. Assumes lock is held."""
        length = data_bytes[0] & 0x0F; payload_start = 1
        pci_byte_val = data_bytes[0]

        if length == 0: # SF length escape
            if dlc < 2: self._log(f"Error: UDS SF LL DLC {dlc} < 2 ID {arbitration_id:X}. Discarding."); return
            length = data_bytes[1]; payload_start = 2
            if length == 0: self._log(f"Error: UDS SF LL length is 0 ID {arbitration_id:X}. Discarding."); return
        # Note: ISO 15765-2 allows length > 7 for SF if CAN FD is used, but this tool doesn't support FD yet.
        # Standard CAN only allows SF length 1-7.
        elif length > 7:
            self._log(f"Error: Invalid UDS SF length {length} (PCI: {pci_byte_val:02X}) ID {arbitration_id:X}. Discarding."); return

        expected_dlc_min = length + payload_start
        # Check if DLC is sufficient for the declared payload length
        # Allow DLC=8 even if payload is shorter (standard CAN frame padding)
        if dlc < expected_dlc_min and dlc != 8 :
             self._log(f"Error: UDS SF DLC {dlc} < {expected_dlc_min} for declared length {length} (PCI: {pci_byte_val:02X}) ID {arbitration_id:X}. Discarding."); return

        # Extract payload, ensuring not to read past the actual DLC
        actual_payload_length = min(length, dlc - payload_start)
        payload = data_bytes[payload_start : payload_start + actual_payload_length]

        # Queue format: [pci_byte(s), payload...]
        if payload_start == 1: # Normal SF
            response_entry = [pci_byte_val] + payload
        else: # SF with length escape
            response_entry = [0x00, length] + payload

        self.response_queue.put(response_entry)
        self._reset_isotp_state()


    def _handle_ff(self, arbitration_id: int, data_bytes: List[int], dlc: int):
        """Handles an ISO-TP First Frame. Assumes lock is held."""
        if dlc < 2: self._log(f"Error: UDS FF DLC {dlc} < 2 ID {arbitration_id:X}. Resetting."); self._reset_isotp_state(); return

        len_high_nibble = data_bytes[0] & 0x0F
        self._isotp_expected_len = (len_high_nibble << 8) + data_bytes[1]
        payload_start_index = 2
        pci_byte_ff = data_bytes[0]

        # ISO-TP max length is 4095 (0xFFF)
        if self._isotp_expected_len == 0 or self._isotp_expected_len > 4095:
              self._log(f"Error: Invalid/Unsupported UDS FF len {self._isotp_expected_len} ID {arbitration_id:X}. Resetting.")
              self._reset_isotp_state(); return

        if dlc < payload_start_index:
            self._log(f"Error: UDS FF DLC {dlc} < header size {payload_start_index} ID {arbitration_id:X}. Resetting.")
            self._reset_isotp_state(); return

        # Extract initial payload data from the FF
        ff_payload_len = dlc - payload_start_index
        self._isotp_buffer = data_bytes[payload_start_index:dlc]

        # Check if FF contains the entire message (unlikely but possible)
        if len(self._isotp_buffer) >= self._isotp_expected_len:
            final_payload = self._isotp_buffer[:self._isotp_expected_len]
            # Queue format: [ff_pci, len_low, payload...]
            response_entry = [pci_byte_ff, data_bytes[1]] + final_payload
            self.response_queue.put(response_entry)
            self._reset_isotp_state()
        else:
            # Prepare for Consecutive Frames
            self._isotp_frame_index = 1 # Expect CF with index 1 next
            self._isotp_state = ISOTPState.WAIT_CF
            self._isotp_target_id = arbitration_id # Expect subsequent frames from this ID
            self._isotp_flow_control_id = arbitration_id # ID to send FC messages back to (via req ID)
            self._isotp_frames_since_fc = 0
            self._isotp_block_size = 0 # Wait for FC from sender if they send one
            self._isotp_stmin = 0.0    # Default to 0 if no FC received

            # Send initial Flow Control (CTS) to indicate readiness for CFs
            # Block Size (BS) = 0 means send all frames without waiting for another FC
            # Separation Time (STmin) = 0 means no delay required between CFs
            self._send_flow_control(flow_status=FC_STATUS_CTS, block_size=0, st_min_ms=0)


    def _handle_cf(self, arbitration_id: int, data_bytes: List[int], dlc: int):
        """Handles an ISO-TP Consecutive Frame. Assumes lock is held."""
        if dlc < 1: self._log(f"Error: UDS CF DLC {dlc} < 1 ID {arbitration_id:X}. Resetting."); self._reset_isotp_state(); return

        current_index = data_bytes[0] & 0x0F
        expected_wrapped_index = self._isotp_frame_index % 16

        if current_index != expected_wrapped_index:
            self._log(f"Error: UDS CF index mismatch ID {arbitration_id:X}. Expected {expected_wrapped_index}, got {current_index}. Resetting.")
            self._reset_isotp_state()
            return

        # Append payload data from CF (byte 1 onwards, up to DLC limit)
        bytes_to_add = data_bytes[1 : dlc]
        self._isotp_buffer.extend(bytes_to_add)
        self._isotp_frame_index += 1
        self._isotp_frames_since_fc += 1

        # Check if the full message is received
        if len(self._isotp_buffer) >= self._isotp_expected_len:
            final_payload = self._isotp_buffer[:self._isotp_expected_len]
            # Reconstruct the FF PCI and length bytes for consistency in queue format
            len_high_nibble = (self._isotp_expected_len >> 8) & 0x0F
            len_low_byte = self._isotp_expected_len & 0xFF
            ff_pci = (PCI_TYPE_FF << 4) | len_high_nibble
            # Queue format: [ff_pci, len_low, payload...]
            response_entry = [ff_pci, len_low_byte] + final_payload
            self.response_queue.put(response_entry);
            self._reset_isotp_state() # Reset state after completion
        # Check if we need to send another Flow Control (if Block Size was set)
        elif self._isotp_block_size > 0 and self._isotp_frames_since_fc >= self._isotp_block_size:
            self._isotp_frames_since_fc = 0 # Reset counter for this block
            # Send CTS Flow Control with the same BS and STmin values
            st_min_ms_int = int(self._isotp_stmin * 1000) # Convert STmin seconds back to ms for sending
            self._send_flow_control(flow_status=FC_STATUS_CTS, block_size=self._isotp_block_size, st_min_ms=st_min_ms_int)


    def _handle_fc(self, arbitration_id: int, data_bytes: List[int]):
        """Handles an incoming ISO-TP Flow Control frame. Assumes lock is held."""
        # This function is typically relevant when WE are the SENDER of a multi-frame message.
        # As a receiver, we generally SEND FC, not receive it, except perhaps error cases.
        # However, we might need to handle it if the sender re-sends an FC or sends WT/OVFLW.
        if len(data_bytes) < 3: self._log(f"Warn: Short FC frame received from {arbitration_id:X}. Len {len(data_bytes)}. Ign."); return

        flow_status = data_bytes[0] & 0x0F
        block_size = data_bytes[1]
        st_min_raw = data_bytes[2]

        # Decode STmin (Separation Time Minimum)
        if 0 <= st_min_raw <= 0x7F: st_min_ms = st_min_raw # 0-127 ms
        elif 0xF1 <= st_min_raw <= 0xF9: st_min_ms = (st_min_raw - 0xF0) * 0.1 # 100-900 us -> convert to ms
        else: st_min_ms = 127 # Per spec, treat reserved/invalid values as max standard value (127ms)

        st_min_sec = st_min_ms / 1000.0
        flow_status_str = {FC_STATUS_CTS: "CTS", FC_STATUS_WT: "WAIT", FC_STATUS_OVFLW: "OVFLW"}.get(flow_status, "?")
        # self._log(f"Received FC from {arbitration_id:X}: FS={flow_status_str}, BS={block_size}, STmin={st_min_ms}ms") # Less verbose logging

        # If we are currently waiting for CF frames (i.e., receiving a multi-frame message)
        if self._isotp_state == ISOTPState.WAIT_CF and arbitration_id == self._isotp_target_id:
             if flow_status == FC_STATUS_CTS:
                 # Store the BS and STmin requested by the sender
                 self._isotp_block_size = block_size
                 self._isotp_stmin = st_min_sec
                 self._isotp_frames_since_fc = 0 # Reset counter as we received a new FC
                 # self._log(f"  -> Updated receiver params: BS={block_size}, STmin={st_min_sec:.3f}s")
             elif flow_status == FC_STATUS_WT:
                 self._log("Received WAIT from sender, pausing reception may be needed (not implemented, continuing...)")
                 # TODO: Implement wait logic if required by pausing CF sending or handling
             elif flow_status == FC_STATUS_OVFLW:
                 self._log("Error: Sender reported OVFLW. Resetting state.")
                 self._reset_isotp_state()
        else:
            # Received FC in an unexpected state (e.g., IDLE or when sending)
            # self._log("Warn: Received FC in unexpected state or from unexpected ID. Ignored.")
            pass # Generally ignore FCs if not actively receiving a multi-frame message

    def register_live_dashboard_processor(self, processor: Optional[ILiveDataProcessor]):
        if processor is None: self._log("Unregistering live processor."); self.live_dashboard_processor = None
        elif hasattr(processor, 'TARGET_IDS') and callable(getattr(processor, 'process_message', None)):
             target_ids_str = ", ".join(f"{tid:X}" for tid in processor.TARGET_IDS) if processor.TARGET_IDS else "None"; self._log(f"Registering live processor targeting IDs: {target_ids_str}"); self.live_dashboard_processor = processor
        else: self._log("Error: Invalid live processor passed."); self.live_dashboard_processor = None