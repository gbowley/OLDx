# can_communication.py

# Handles communication with the CANBUS

import can
import time
import threading
import queue
import logging # Not strictly used in this version, but good practice
import traceback
from typing import Optional, List, Tuple, Dict, Any, Set, Union # Ensure Union is imported
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
UDS_REQUEST_ID: int = 0x7E0
UDS_RESPONSE_ID: int = 0x7E8
ABS_REQUEST_ID: int = 0x6F4 # KWP ID for ABS
ABS_RESPONSE_ID: int = 0x6F5 # KWP ID for ABS
TCU_REQUEST_ID: int = 0x7E1 # Example, adjust if different
TCU_RESPONSE_ID: int = 0x7E9 # Example, adjust if different
RELEVANT_RESPONSE_IDS: Set[int] = {UDS_RESPONSE_ID, ABS_RESPONSE_ID, TCU_RESPONSE_ID}
# Define which IDs strictly use ISO-TP multi-frame logic (Reverted to original)
UDS_RESPONSE_IDS_FOR_ISOTP: Set[int] = {UDS_RESPONSE_ID, TCU_RESPONSE_ID}


# Command Mapping - Inc. Faults, KWP, OBD
COMMANDS: Dict[str, Optional[Tuple[int, List[int]]]] = {
    'getVin': (UDS_REQUEST_ID, [0x02, 0x09, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00]),
    'getEngineFaultsNormal': (UDS_REQUEST_ID, [0x02, 0x19, 0x02, 0x09, 0x00, 0x00, 0x00, 0x00]), # Read DTCs by status mask (0x09 = confirmed)
    'getEngineFaultsSpecial': (UDS_REQUEST_ID, [0x02, 0x19, 0x01, 0xFF, 0x00, 0x00, 0x00, 0x00]), # Read DTCs by type (0xFF = all) - less common
    'getEngineFaultsNormalPending': (UDS_REQUEST_ID, [0x02, 0x19, 0x02, 0x08, 0x00, 0x00, 0x00, 0x00]), # Use $19 02 with pending mask (e.g., 0x08)
    'getGearboxFaultsNormal': (TCU_REQUEST_ID, [0x02, 0x19, 0x02, 0xFF, 0x00, 0x00, 0x00, 0x00]), # Assuming TCU uses UDS
    'getGearboxFaultsSpecial': (TCU_REQUEST_ID, [0x02, 0x19, 0x01, 0xFF, 0x00, 0x00, 0x00, 0x00]),
    'clearEngineFaultsNormal': (UDS_REQUEST_ID, [0x04, 0x14, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00]), # Clear all DTCs
    'clearEngineFaultsSpecial': (UDS_REQUEST_ID, [0x04, 0x14, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00]),
    'clearGearboxFaultsNormal': (TCU_REQUEST_ID, [0x04, 0x14, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00]),
    'clearGearboxFaultsSpecial': (TCU_REQUEST_ID, [0x04, 0x14, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00]),
    'getObdConfirmedFaults': (UDS_REQUEST_ID, [0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), # OBD Mode $03
    'getObdPendingFaults': (UDS_REQUEST_ID, [0x01, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),   # OBD Mode $07
    # KWP Commands referenced directly by 's' name prefix in diagnostics.py
    's06F4021089': (ABS_REQUEST_ID, [0x02, 0x10, 0x89, 0x00, 0x00, 0x00, 0x00, 0x00]), # Session Standby for Bosch ABS
    's06F4031300FF': (ABS_REQUEST_ID, [0x03, 0x13, 0x00, 0xFF]), # KWP Read DTC (Service $13, Type $00, Group $FF=All) - Preferred
    's06F4041800FF00': (ABS_REQUEST_ID, [0x04, 0x18, 0x00, 0xFF, 0x00]), # KWP Read DTC by Status (Service $18, Type $00, Status $FF=All) - Alternative
    's06F40314FF00': (ABS_REQUEST_ID, [0x03, 0x14, 0xFF, 0x00]), # KWP Clear DTC? (Service $14, Group $FF=All)
    'monitorAllStart': None, 'monitorAllStop': None, # Placeholder for potential future direct control
    'enableFlowControl': None, 'disableFlowControl': None, # Placeholder
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
    WAIT_FC = 2 # State for when we are sending and waiting for a Flow Control from the receiver

# --- HELPER FUNCTION ---
def decode_nrc(nrc: int) -> str:
    """Decodes common Negative Response Codes."""
    nrc_map = {
        0x10: "General Reject",
        0x11: "Service Not Supported",
        0x12: "SubFunction Not Supported",
        0x13: "Incorrect Message Length Or Invalid Format",
        0x14: "Response Too Long",
        0x21: "Busy Repeat Request",
        0x22: "Conditions Not Correct",
        0x24: "Request Sequence Error",
        0x31: "Request Out Of Range",
        0x33: "Security Access Denied",
        0x35: "Invalid Key",
        0x36: "Exceeded Number Of Attempts",
        0x37: "Required Time Delay Not Expired",
        0x78: "Request Correctly Received - Response Pending",
        0x7E: "SubFunction Not Supported In Active Session",
        0x7F: "Service Not Supported In Active Session",
        # Add more NRC codes here if needed
    }
    return nrc_map.get(nrc, f"Unknown NRC {nrc:02X}")
# --- END HELPER FUNCTION ---

class ILiveDataProcessor:
    """Interface for components that process live data from CAN messages."""
    TARGET_IDS: Set[int] = set() # Define which CAN IDs this processor is interested in
    def process_message(self, msg: can.Message):
        """Processes an incoming CAN message relevant to live data."""
        raise NotImplementedError

# --- Define ICanRawMessageProcessor Interface ---
class ICanRawMessageProcessor:
    """
    Interface for components that want to process raw CAN messages
    and decide if they are interested in a specific message.
    """
    def process_raw_can_message(self, msg: can.Message):
        """Processes an incoming raw CAN message."""
        raise NotImplementedError

    def is_interested(self, arbitration_id: int) -> bool:
        """Checks if the processor is interested in a message with this arbitration ID."""
        raise NotImplementedError

class CanCommunication:
    def __init__(self, channel: Optional[str], gui_queue: queue.Queue, interface: str = 'usb2can', bitrate: int = 500000):
        self.channel: Optional[str] = channel
        self.interface: str = interface
        self.bitrate: int = bitrate
        self.gui_queue: queue.Queue = gui_queue
        self.bus: Optional[can.BusABC] = None
        self.is_connected: bool = False
        self.reader_thread: Optional[threading.Thread] = None
        self.running: bool = False
        self.rx_queue: queue.Queue = queue.Queue(maxsize=500) # Queue for all incoming messages
        self.response_queue: queue.Queue = queue.Queue() # Queue for processed diagnostic responses
        self.notifier: Optional[can.Notifier] = None
        self.live_dashboard_processor: Optional[ILiveDataProcessor] = None
        self.expert_raw_processor: Optional[ICanRawMessageProcessor] = None # ADDED: For CAN Expert Tab

        # ISO-TP state variables
        self._isotp_state: ISOTPState = ISOTPState.IDLE
        self._isotp_target_id: Optional[int] = None # ID we expect multi-frame responses from
        self._isotp_buffer: List[int] = [] # Buffer for assembling multi-frame messages
        self._isotp_expected_len: int = 0 # Expected total length of the multi-frame message
        self._isotp_frame_index: int = 0 # Expected index of the next Consecutive Frame (CF)
        self._isotp_flow_control_id: Optional[int] = None # ID to send Flow Control (FC) to
        self._isotp_block_size: int = 0 # Block Size (BS) from received FC
        self._isotp_stmin: float = 0.0 # Separation Time Minimum (STmin) from received FC, in seconds
        self._isotp_frames_since_fc: int = 0 # Counter for frames received since last FC sent/received
        self._isotp_lock = threading.Lock() # Lock for ISO-TP state variables

        self.debug_log_all_enabled: bool = False # If true, logs all CAN traffic (very verbose)
        self._log_raw_diag_active: bool = False
        self._log_raw_diag_until: float = 0.0
        self.RAW_DIAG_LOG_DURATION: float = 6.0 # Duration to log raw diagnostic frames after a command

    def _log(self, message: str):
        """Sends a log message to the GUI queue."""
        try:
            self.gui_queue.put(("log", str(message)))
        except Exception as e:
            # Fallback if GUI queue fails (e.g., during shutdown)
            print(f"LOG (queue error: {e}): {message}")

    def connect(self) -> bool:
        """Initializes and connects to the CAN bus."""
        if self.is_connected:
            self._log("Already connected.")
            return True
        try:
            self._log(f"Initializing CAN bus: interface={self.interface}, channel='{self.channel}', bitrate={self.bitrate}")
            bus_kwargs = {'channel': self.channel, 'interface': self.interface, 'bitrate': self.bitrate}
            # Attempt to set receive_own_messages=False, handle if not supported
            try:
                self.bus = can.interface.Bus(**bus_kwargs, receive_own_messages=False)
                self._log("Set receive_own_messages=False")
            except TypeError:
                self._log("Warning: Interface might not support receive_own_messages setting.")
                if 'receive_own_messages' in bus_kwargs:
                    del bus_kwargs['receive_own_messages'] # Remove unsupported kwarg
                self.bus = can.interface.Bus(**bus_kwargs) # Try without it

            # Use a single listener that puts all messages onto self.rx_queue
            self.notifier = can.Notifier(self.bus, [self._on_message_received_callback], timeout=0.1)
            self.running = True
            self.reader_thread = threading.Thread(target=self._read_loop, daemon=True, name="CANReadThread")
            self.reader_thread.start()
            self.is_connected = True
            self._log(f"Successfully connected via {self.interface} on '{self.channel}'")
            return True
        except can.CanError as e:
            self._log(f"CAN Connection Error: {e}\nCheck drivers, DLL path, serial number/channel, and device connection.")
        except Exception as e:
            self._log(f"Connect Error: {type(e).__name__}: {e}\n{traceback.format_exc()}")

        self.is_connected = False
        if self.bus:
            try: self.bus.shutdown()
            except Exception as sd_e: self._log(f"Bus shutdown error on fail: {sd_e}")
        if self.notifier:
            try: self.notifier.stop()
            except Exception as ne: self._log(f"Notifier stop error on fail: {ne}")
        self.bus = None
        self.notifier = None
        return False

    def disconnect(self):
        """Disconnects from the CAN bus and cleans up resources."""
        if not self.is_connected:
            self._log("Not connected.")
            return
        self._log("Disconnecting from CAN bus...")
        self.running = False # Signal threads to stop

        if self.notifier:
            try:
                self.notifier.stop(timeout=0.5) # Wait for notifier to stop
                self._log("Notifier stopped.")
            except Exception as e:
                self._log(f"Error stopping notifier: {e}")
            finally:
                self.notifier = None

        if self.reader_thread and self.reader_thread.is_alive():
            self._log("Waiting for reader thread...")
            self.reader_thread.join(timeout=0.5) # Wait for reader thread to finish
            if self.reader_thread.is_alive():
                self._log("Warning: Reader thread did not exit cleanly.")
            else:
                self._log("Reader thread stopped.")
            self.reader_thread = None

        if self.bus:
            try:
                self._log("Shutting down CAN bus...")
                self.bus.shutdown()
                self._log("CAN bus shut down.")
            except Exception as e:
                self._log(f"Error shutting down bus: {e}")
            finally:
                self.bus = None

        self.is_connected = False
        self._log("Clearing queues...")
        # Clear queues to prevent old data processing on reconnect
        while not self.rx_queue.empty():
            try: self.rx_queue.get_nowait()
            except queue.Empty: break
        while not self.response_queue.empty():
            try: self.response_queue.get_nowait()
            except queue.Empty: break
        with self._isotp_lock: # Ensure thread safety for ISO-TP state
            self._reset_isotp_state()
        self._log("Disconnected.")

    def _on_message_received_callback(self, msg: can.Message):
        """Callback for all incoming CAN messages, puts them on rx_queue."""
        if self.running:
            try:
                self.rx_queue.put_nowait(msg) # Non-blocking put
            except queue.Full:
                # Log queue full warning, but throttle to avoid flooding logs
                if hasattr(self, '_last_q_full_log_time'):
                    now = time.monotonic()
                    if now - self._last_q_full_log_time > 5.0: # Log every 5s if still full
                        self._log("Warning: RX queue full. Messages may be lost.")
                        self._last_q_full_log_time = now
                else:
                    self._last_q_full_log_time = time.monotonic()
                    self._log("Warning: RX queue full. Messages may be lost.")
            except Exception as e:
                # Log other errors in callback, also throttled
                if hasattr(self, '_last_rx_err_log_time'):
                    now = time.monotonic()
                    if now - self._last_rx_err_log_time > 10.0: # Log every 10s
                        self._log(f"Error in RX callback putting to queue: {e}")
                        self._last_rx_err_log_time = now
                else:
                    self._last_rx_err_log_time = time.monotonic()
                    self._log(f"Error in RX callback putting to queue: {e}")

    # --- Raw Logging Control ---
    def _activate_raw_diag_logging(self):
        """Activates raw diagnostic logging for a set duration."""
        self._log_raw_diag_active = True
        self._log_raw_diag_until = time.monotonic() + self.RAW_DIAG_LOG_DURATION
        self._log(f"[RAW_DIAG_RX] Logging enabled for {self.RAW_DIAG_LOG_DURATION}s")

    def _deactivate_raw_diag_logging(self):
        """Deactivates raw diagnostic logging."""
        if self._log_raw_diag_active: # Only log if it was active
            self._log_raw_diag_active = False
            self._log("[RAW_DIAG_RX] Logging disabled.")

    # --- Read Loop with Raw Logging ---
    def _read_loop(self):
        """Processes messages from the rx_queue."""
        self._log("CAN Read Loop started.")
        while self.running:
            try:
                msg = self.rx_queue.get(timeout=0.1) # Wait for message with timeout

                # --- Raw Diagnostic Logging Check ---
                if self._log_raw_diag_active:
                    now = time.monotonic()
                    if now < self._log_raw_diag_until:
                        # Log only relevant diagnostic response IDs raw
                        if msg.arbitration_id in RELEVANT_RESPONSE_IDS:
                            self._log(f"[RAW_DIAG_RX] ID={msg.arbitration_id:03X} DLC={msg.dlc} Data={msg.data.hex().upper()}")
                    else:
                        self._deactivate_raw_diag_logging() # Automatically disable after duration
                # --- End Raw Diagnostic Logging ---

                # --- Standard Message Routing ---
                is_diagnostic_response = msg.arbitration_id in RELEVANT_RESPONSE_IDS

                # --- Live Dashboard Processor ---
                processor = self.live_dashboard_processor
                is_live_data = False
                if processor and hasattr(processor, 'TARGET_IDS'):
                    is_live_data = msg.arbitration_id in processor.TARGET_IDS

                if is_live_data and processor:
                    try:
                        if callable(getattr(processor, 'process_message', None)):
                            processor.process_message(msg) # Assuming live_dashboard takes the full msg
                        else:
                            self._log(f"Error: Live processor for ID {msg.arbitration_id:X} is missing process_message method.");
                            self.live_dashboard_processor = None # Potentially unregister bad processor
                    except Exception as live_e:
                        self._log(f"Error processing live data for ID {msg.arbitration_id:X}: {live_e}")

                # --- Diagnostic Response Parser ---
                if is_diagnostic_response: # This was your original condition for _parse_incoming_message
                    try:
                        self._parse_incoming_message(msg) # Pass to ISO-TP/KWP parser
                    except Exception as parse_e:
                        self._log(f"Error parsing diagnostic response for ID {msg.arbitration_id:X}: {parse_e}")


                # --- Expert Raw Processor ---
                if self.expert_raw_processor:
                    try:
                        if self.expert_raw_processor.is_interested(msg.arbitration_id):
                            self.expert_raw_processor.process_raw_can_message(msg)
                    except Exception as exp_e:
                        # Add a throttle for logging this error to avoid flooding
                        if not hasattr(self, '_last_expert_proc_error_time') or \
                           (time.monotonic() - getattr(self, '_last_expert_proc_error_time', 0) > 5.0):
                            self._log(f"Error in expert raw processor: {type(exp_e).__name__} - {exp_e}")
                            setattr(self, '_last_expert_proc_error_time', time.monotonic())
                # --- END Expert Raw Processor ---

            except queue.Empty:
                continue # Normal timeout, loop again
            except Exception as e:
                self._log(f"Error in CAN read loop: {e}")
                # traceback.print_exc() # Uncomment for detailed debugging if needed
                time.sleep(0.1) # Small delay before retrying on error
        self._log("CAN Read Loop stopped.")

    # _send_can_message
    def _send_can_message(self, arbitration_id: int, data: Any, is_extended: bool = False, is_remote: bool = False) -> bool:
        """
        Internal method to send a single CAN message.
        Handles data type conversion and padding.
        Includes RTR frame support.
        """
        if not self.is_connected or not self.bus:
            self._log("Error: Cannot send CAN message, not connected.")
            return False
        try:
            if isinstance(data, str): # Assume hex string
                data_bytes = bytes.fromhex(data)
            elif isinstance(data, (list, tuple)): # Assume list/tuple of ints
                if any(not isinstance(b, int) or b < 0 or b > 255 for b in data):
                    raise ValueError("Data bytes in list/tuple must be integers between 0 and 255.")
                data_bytes = bytes(data)
            elif isinstance(data, bytes):
                data_bytes = data
            else:
                self._log(f"Error: Invalid CAN data type provided: {type(data)}")
                return False

            actual_dlc = len(data_bytes)
            if is_remote:
                # For RTR, DLC indicates requested length. Data itself is not sent.
                # python-can's Message object handles this when is_remote_frame=True.
                pass # actual_dlc is already len(data_bytes), used for dlc field in Message

            if actual_dlc > 8 and not is_remote : # Standard CAN Frame data limit
                 self._log(f"Error: CAN data length ({actual_dlc}) for DLC exceeds 8 bytes. ID={arbitration_id:03X}")
                 return False


            # Padding for can.Message object data attribute if not RTR.
            # For RTR, data field in Message object is typically ignored by backend, DLC matters.
            if not is_remote:
                if len(data_bytes) < 8:
                    padded_data_for_msg_obj = data_bytes + bytes([0xAA] * (8 - len(data_bytes)))
                else:
                    padded_data_for_msg_obj = data_bytes
            else: # For RTR, data field often empty or not used for TX, DLC is key.
                  # Let's pass empty bytes for data to Message if RTR, DLC is set by actual_dlc.
                padded_data_for_msg_obj = b''


            message = can.Message(
                arbitration_id=arbitration_id,
                data=padded_data_for_msg_obj,
                is_extended_id=is_extended,
                is_remote_frame=is_remote,
                is_fd=False,
                dlc=actual_dlc # Correct DLC for the frame
            )
            self.bus.send(message, timeout=0.2)

            log_data_str = data_bytes.hex().upper() if not is_remote else "(RTR Frame)"
            self._log(f"Sent: ID={arbitration_id:03X} DLC={actual_dlc} Data={log_data_str} Ext={is_extended} RTR={is_remote}")
            return True

        except ValueError as ve:
            self._log(f"Data Error sending CAN message (ID: {arbitration_id:03X}): {ve}")
        except can.CanError as e:
            self._log(f"CAN Bus Error sending message (ID: {arbitration_id:03X}): {e}")
        except Exception as e:
            self._log(f"Unexpected error sending CAN message (ID: {arbitration_id:03X}): {type(e).__name__} - {e}")
        return False

    def send_command(self, command_name: str, timeout: float = 3.0,
                     req_id: Optional[int] = None, data: Optional[Union[List[int], bytes]] = None,
                     is_extended: bool = False,
                     expected_response_service_id: Optional[int] = None) -> Tuple[bool, Optional[List[int]]]:
        """
        Sends a diagnostic command and waits for a potentially multi-frame response.
        Response_data format from queue is now consistently what this method expects from original version:
          - UDS SF: [pci_byte(incl.len), SID, ...] or [0x00, actual_len, SID, ...]
          - UDS MF: [ff_pci, len_low, SID, ...] (assembled payload, with FF PCI info prepended)
          - KWP:    [SID, actual_payload_bytes...]
          - NRC:    Protocol-specific NRC structure starting with its SID (e.g., 0x7F)
        """
        if not self.is_connected:
            self._log(f"Error: Cannot send '{command_name}', not connected.")
            return False, None

        # --- Resolve Command ---
        resolved_req_id: Optional[int] = req_id
        resolved_data: Optional[Union[List[int], bytes]] = data
        resolved_is_extended: bool = is_extended
        request_service_id: Optional[int] = None # The SID we are sending

        if resolved_req_id is None or resolved_data is None:
            if command_name.startswith('p'):
                try:
                    did_hex = command_name[1:]
                    if not (len(did_hex) == 4 and all(c in '0123456789abcdefABCDEF' for c in did_hex)):
                        raise ValueError("DID hex must be 4 valid hex characters.")
                    did_int = int(did_hex, 16)
                    resolved_req_id = UDS_REQUEST_ID
                    resolved_data = [0x03, 0x22, (did_int >> 8) & 0xFF, did_int & 0xFF]
                    request_service_id = 0x22
                except ValueError as e:
                    self._log(f"Error: Invalid performance command format '{command_name}': {e}")
                    return False, None
            elif command_name.startswith('s'):
                try:
                    if len(command_name) < 7 : raise ValueError("Raw command too short.")
                    raw_id_hex = command_name[1:5]
                    raw_data_hex = command_name[5:]
                    if not (all(c in '0123456789abcdefABCDEF' for c in raw_id_hex) and len(raw_id_hex) <=4 ): # Allow 3 or 4 hex for ID
                         raise ValueError("Raw command ID part invalid.")
                    if not (all(c in '0123456789abcdefABCDEF' for c in raw_data_hex) and len(raw_data_hex) % 2 == 0):
                         raise ValueError("Raw command data part invalid.")
                    resolved_req_id = int(raw_id_hex, 16)
                    resolved_data = bytes.fromhex(raw_data_hex)
                    if len(resolved_data) > 1 and resolved_req_id not in [ABS_REQUEST_ID]: # UDS like, SID is usually byte 1 after PCI
                        request_service_id = resolved_data[1]
                    elif len(resolved_data) > 0: # KWP like or simple command, SID might be first byte
                        request_service_id = resolved_data[0]
                except ValueError as e:
                    self._log(f"Error parsing raw send command '{command_name}': {e}")
                    return False, None
            else:
                command_tuple = COMMANDS.get(command_name)
                if command_tuple is None:
                    if command_name in COMMANDS and COMMANDS[command_name] is None:
                        self._log(f"Executing local action (no CAN send): {command_name}")
                        # Handle local actions if any specific logic needed here
                        return True, None
                    else:
                        self._log(f"Error: Command '{command_name}' not recognized or not configured.")
                        return False, None
                resolved_req_id, data_list = command_tuple
                resolved_data = bytes(data_list)
                if len(data_list) > 1: request_service_id = data_list[1] # PCI often first, then SID

        if resolved_req_id is None or resolved_data is None:
            self._log(f"Internal Error: Could not determine CAN message data for '{command_name}'.")
            return False, None

        # --- Prepare for Response ---
        while not self.response_queue.empty():
            try:
                stale_msg = self.response_queue.get_nowait()
                self._log(f"Cleared stale message from response queue: {stale_msg}")
            except queue.Empty:
                break

        with self._isotp_lock:
            self._reset_isotp_state()
            # Set target ID for ISO-TP responses if applicable. UDS_RESPONSE_IDS_FOR_ISOTP is now corrected.
            if resolved_req_id in UDS_RESPONSE_IDS_FOR_ISOTP or resolved_req_id == UDS_REQUEST_ID:
                self._isotp_target_id = resolved_req_id + 8

        # --- Activate Raw Logging & Send Command ---
        self._activate_raw_diag_logging()
        # _send_can_message's is_remote defaults to False, which is correct for diagnostic commands.
        if not self._send_can_message(resolved_req_id, resolved_data, resolved_is_extended):
            self._deactivate_raw_diag_logging()
            return False, None

        # --- Wait for Response ---
        start_time = time.monotonic()
        response_received: Optional[List[int]] = None
        success_flag = False
        is_kwp_request = resolved_req_id == ABS_REQUEST_ID

        while True:
            current_time = time.monotonic()
            if current_time - start_time > timeout:
                self._log(f"Timeout ({timeout}s) waiting for response to '{command_name}' (ReqID: {resolved_req_id:X})")
                with self._isotp_lock: self._reset_isotp_state()
                success_flag = False; response_received = None
                break

            try:
                response_data = self.response_queue.get(block=True, timeout=0.1)

                service_id_index = -1
                response_format_type = "Unknown"
                actual_service_id = None

                if not response_data : # Should not be empty if valid
                    self._log(f"Received empty/invalid response fragment from queue for {command_name}. Continuing wait.")
                    continue

                if is_kwp_request:
                    # KWP: response_data from queue is [SID, actual_payload_bytes...]
                    # This is because _parse_incoming_message (corrected) for ABS_RESPONSE_ID puts data_bytes[1:]
                    service_id_index = 0 # SID is the first element
                    response_format_type = "KWP"
                    if len(response_data) > service_id_index:
                        actual_service_id = response_data[service_id_index]
                    else:
                        self._log(f"Received invalid/short KWP response fragment: {response_data}. Continuing wait.")
                        continue
                else: # UDS/ISO-TP path
                    # UDS: response_data from queue is [PCI_byte(s), SID, data_bytes...]
                    # This is because _handle_sf/_handle_ff (corrected) put PCI info first.
                    if not response_data: continue # Should not happen here
                    first_byte = response_data[0]
                    pci_type = (first_byte >> 4) & 0x0F

                    if pci_type == PCI_TYPE_FF: # UDS MF: [ff_pci, len_low, SID, ...]
                        if len(response_data) >= 3: service_id_index = 2; response_format_type = "UDS_MF"
                    elif pci_type == PCI_TYPE_SF: # UDS SF: [pci_byte(incl.len), SID, ...]
                        if len(response_data) >= 2: service_id_index = 1; response_format_type = "UDS_SF"
                    elif first_byte == 0x00 and len(response_data) >= 3: # UDS SF length escape [0x00, Len, SID, ...]
                        service_id_index = 2; response_format_type = "UDS_SF_ESC"

                    if service_id_index != -1 and len(response_data) > service_id_index:
                        actual_service_id = response_data[service_id_index]
                    else:
                        self._log(f"Received ambiguous/short UDS response from queue: {response_data}. PCI Type: {pci_type:X}. Continuing wait.")
                        continue

                if actual_service_id is None:
                    self._log(f"Could not determine actual_service_id for response: {response_data}. Format guess: {response_format_type}. Continuing wait.")
                    continue

                # --- Validate Response ---
                is_negative_response = False
                nrc = 0
                req_serv_echo = 0 # Service ID echoed in the NRC response

                if actual_service_id == 0x7F: # Negative Response SID
                    is_negative_response = True
                    if is_kwp_request:
                        # KWP NRC from queue: [0x7F, echoed_SID, NRC_code, ...]
                        req_serv_echo = response_data[1] if len(response_data) > 1 else 0
                        nrc = response_data[2] if len(response_data) > 2 else 0
                    else: # UDS NRC
                        # UDS NRC from queue: [PCI(s), 0x7F, echoed_SID, NRC_code, ...]
                        # SID was at service_id_index, so echoed_SID is next, NRC is after that
                        echoed_sid_payload_index = service_id_index + 1
                        nrc_payload_index = service_id_index + 2
                        if len(response_data) > nrc_payload_index:
                            req_serv_echo = response_data[echoed_sid_payload_index]
                            nrc = response_data[nrc_payload_index]
                        else: # Cannot reliably extract NRC
                            self._log(f"Warning: Short UDS NRC response received: {response_data}")
                            req_serv_echo = request_service_id if request_service_id is not None else 0xFF # Best guess
                            nrc = 0 # Unknown NRC

                if is_negative_response:
                    if request_service_id is None or req_serv_echo == request_service_id:
                        self._log(f"Received NRC: {nrc:02X} ({decode_nrc(nrc)}) for Service ${req_serv_echo:02X} (Command: {command_name}) Format: {response_format_type}")
                        with self._isotp_lock: self._reset_isotp_state()
                        success_flag = False
                        response_received = response_data # Return full NRC frame
                        break
                    else:
                        self._log(f"Ignoring late/mismatched NRC: {nrc:02X} for Service ${req_serv_echo:02X} while waiting for Service ${request_service_id if request_service_id else 'Any'} (Cmd: {command_name})")
                        continue # Ignore this NRC and continue waiting

                # Check for Positive Response Match (if not an NRC)
                if expected_response_service_id is not None:
                    if actual_service_id == expected_response_service_id:
                        success_flag = True
                        response_received = response_data
                        break # Correct positive response received
                    else: # Mismatched SID
                        log_data_hex = bytes(response_data).hex().upper()
                        self._log(f"Mismatched positive response (Expected SID: {expected_response_service_id:02X}, Got SID: {actual_service_id:02X}, Format: {response_format_type}, Data: {log_data_hex}) for {command_name}")
                        success_flag = False # Explicitly fail
                        response_received = response_data # Return the mismatched data
                        break # Exit loop, a response was received, but it was not the expected one
                else: # Accept first positive response if no specific SID expected
                    success_flag = True
                    response_received = response_data
                    break # First positive response is acceptable

            except queue.Empty:
                continue # Normal timeout from response_queue.get(), loop again
            except Exception as e:
                self._log(f"Error processing response queue for command '{command_name}': {e}\n{traceback.format_exc()}")
                success_flag = False; response_received = None
                break

        self._deactivate_raw_diag_logging()
        return success_flag, response_received

    # _send_flow_control
    def _send_flow_control(self, flow_status: int = FC_STATUS_CTS, block_size: int = 0, st_min_ms: int = 0):
        if self._isotp_flow_control_id is None:
            self._log("Error: Cannot send Flow Control, _isotp_flow_control_id (ECU's response ID) not set.")
            return

        fc_destination_id: Optional[int] = None
        # Determine destination ID for FC (usually the ECU's request ID)
        if self._isotp_flow_control_id == UDS_RESPONSE_ID:
            fc_destination_id = UDS_REQUEST_ID
        elif self._isotp_flow_control_id == TCU_RESPONSE_ID:
            fc_destination_id = TCU_REQUEST_ID
        elif 0x7E8 <= self._isotp_flow_control_id <= 0x7EF: # General UDS physical response range
            fc_destination_id = self._isotp_flow_control_id - 8
        # Add other specific ISO-TP capable response IDs here if needed

        if fc_destination_id is None:
            self._log(f"Warning: No mapping to determine FC destination ID from ECU response ID {self._isotp_flow_control_id:X}. Suppressing FC.")
            return

        # Explicitly prevent sending FC to known KWP request IDs
        if fc_destination_id == ABS_REQUEST_ID:
            self._log(f"Warning: Suppressing FC frame potentially intended for KWP request ID {fc_destination_id:X} (derived from {self._isotp_flow_control_id:X}).")
            return

        # STmin encoding
        st_min_can_byte = 0x00 # Default to 0ms
        if 0 <= st_min_ms <= 127: # 0-127 ms
            st_min_can_byte = int(st_min_ms)
        elif 0.1 <= st_min_ms < 1.0: # For 100us to 900us (which is 0.1ms to 0.9ms)
            # ISO 15765-2: F1-F9 for 100us to 900us
            st_min_can_byte = 0xF0 + int(st_min_ms * 10)
        elif st_min_ms != 0 : # If not 0, but not in ranges above
            self._log(f"Warning: STmin {st_min_ms}ms out of standard encodable range for FC. Using 0ms (byte 0x00).")
            st_min_can_byte = 0x00 # Fallback

        fc_pci = (PCI_TYPE_FC << 4) | (flow_status & 0x0F)
        fc_data = [fc_pci, block_size & 0xFF, st_min_can_byte]
        fs_str = {FC_STATUS_CTS:"CTS", FC_STATUS_WT:"WT", FC_STATUS_OVFLW:"OVFLW"}.get(flow_status,"?")
        self._log(f"Sending Flow Control ({fs_str}, BS={block_size}, STmin={st_min_ms}ms -> byte 0x{st_min_can_byte:02X}) to ID {fc_destination_id:03X}")
        self._send_can_message(fc_destination_id, fc_data)


    def _reset_isotp_state(self):
        """Resets ISO-TP state variables. Assumes lock is held if called from multiple threads."""
        if self._isotp_state != ISOTPState.IDLE:
             pass # Optional: self._log(f"Resetting ISO-TP from state: {self._isotp_state.name}")
        self._isotp_state = ISOTPState.IDLE
        self._isotp_target_id = None
        self._isotp_buffer = []
        self._isotp_expected_len = 0
        self._isotp_frame_index = 0
        self._isotp_flow_control_id = None # ECU's response ID that initiated this ISO-TP session
        self._isotp_block_size = 0
        self._isotp_stmin = 0.0
        self._isotp_frames_since_fc = 0

    # _parse_incoming_message
    def _parse_incoming_message(self, msg: can.Message):
        """Parses incoming diagnostic messages, handling KWP and ISO-TP."""
        if not hasattr(msg, 'data') or not msg.data or msg.dlc == 0:
            return

        data_bytes = list(msg.data)
        arbitration_id = msg.arbitration_id

        try:
            # Handle non-ISO-TP IDs first (e.g., KWP on ABS_RESPONSE_ID)
            # UDS_RESPONSE_IDS_FOR_ISOTP is now corrected (excludes ABS_RESPONSE_ID)
            if arbitration_id not in UDS_RESPONSE_IDS_FOR_ISOTP:
                if arbitration_id == ABS_RESPONSE_ID:
                    # KWP responses: Put payload starting from the SID byte onto the queue.
                    # Example: Raw CAN [02 50 89 ...] (Len, SID, Data...) -> Queue gets [0x50, 0x89, ...]
                    if msg.dlc >= 2: # KWP response should have at least format/len byte and SID byte
                        payload_kwp = data_bytes[1:msg.dlc] # Assumes SID is data_bytes[1]
                        if payload_kwp: # Ensure there's something to put
                            self.response_queue.put(payload_kwp)
                        # else: self._log(f"KWP (ABS) Warning: Empty payload after stripping assumed format byte for ID {arbitration_id:X}")
                    # else: self._log(f"KWP (ABS) Warning: Message too short (DLC={msg.dlc}) for ID {arbitration_id:X}")
                # else: # Other non-ISO-TP diagnostic IDs could be handled here if needed
                #    self._log(f"Message from non-ISO-TP ID {arbitration_id:X} not processed by diagnostic parser.")
                return # Stop processing for non-ISO-TP IDs handled here or ignored

            # --- ISO-TP Logic for UDS_RESPONSE_IDS_FOR_ISOTP ---
            pci_byte = data_bytes[0]
            frame_type = (pci_byte >> 4) & 0x0F

            # Check for valid ISO-TP PCI type before acquiring lock for efficiency
            if frame_type not in [PCI_TYPE_SF, PCI_TYPE_FF, PCI_TYPE_CF, PCI_TYPE_FC]:
                # self._log(f"Ignoring non-ISO-TP frame from ISO-TP ID {arbitration_id:X}. PCI byte: {pci_byte:02X}")
                return


            with self._isotp_lock:
                if self._isotp_state == ISOTPState.IDLE:
                    if frame_type == PCI_TYPE_SF: self._handle_sf(arbitration_id, data_bytes, msg.dlc)
                    elif frame_type == PCI_TYPE_FF: self._handle_ff(arbitration_id, data_bytes, msg.dlc)
                    elif frame_type == PCI_TYPE_CF:
                        self._log(f"Warn: Unexpected CF from ID {arbitration_id:X} in IDLE. Resetting."); self._reset_isotp_state()
                    elif frame_type == PCI_TYPE_FC:
                        # self._log(f"Warn: Unexpected FC from ID {arbitration_id:X} in IDLE. Handling.") # Can happen if ECU sends FC proactively
                        self._handle_fc(arbitration_id, data_bytes) # Attempt to handle it

                elif self._isotp_state == ISOTPState.WAIT_CF:
                    if arbitration_id != self._isotp_target_id:
                        # self._log(f"Debug: Ignoring msg from {arbitration_id:X} while waiting for {self._isotp_target_id:X}")
                        return # Ignore messages from other IDs while assembling a multi-frame response

                    if frame_type == PCI_TYPE_CF: self._handle_cf(arbitration_id, data_bytes, msg.dlc)
                    elif frame_type == PCI_TYPE_FC:
                        # self._log(f"Received FC from {arbitration_id:X} while in WAIT_CF. Handling.")
                        self._handle_fc(arbitration_id, data_bytes) # Handle FC (e.g., a WAIT frame)
                    else: # SF or FF received while expecting CF
                        self._log(f"Error: Expected CF from {arbitration_id:X}, got PCI type {frame_type:X}. Resetting ISO-TP.")
                        self._reset_isotp_state()
                        # Attempt to process the new frame if it's a start frame (SF or FF)
                        if frame_type == PCI_TYPE_SF: self._handle_sf(arbitration_id, data_bytes, msg.dlc)
                        elif frame_type == PCI_TYPE_FF: self._handle_ff(arbitration_id, data_bytes, msg.dlc)

                elif self._isotp_state == ISOTPState.WAIT_FC: # We are sending, and waiting for an FC from receiver
                    if frame_type == PCI_TYPE_FC:
                        self._handle_fc(arbitration_id, data_bytes)
                    else:
                        self._log(f"Warn: Expected FC but received PCI type {frame_type:X} from {arbitration_id:X} while in WAIT_FC. Ignoring.")
                # else: self._log(f"Warn: Message from {arbitration_id:X} received in unhandled ISO-TP state: {self._isotp_state.name}")

        except IndexError as e:
            self._log(f"Parse Error (Index): {e}, Data: {bytes(msg.data).hex()}, ID: {arbitration_id:X}")
            with self._isotp_lock: self._reset_isotp_state()
        except Exception as e:
            self._log(f"Parse Error (Unexpected): {type(e).__name__} - {e}, Data: {bytes(msg.data).hex()}, ID: {arbitration_id:X}")
            with self._isotp_lock: self._reset_isotp_state()

    # --- ISO-TP Frame Handlers (Reverted to Original logic for queue format) ---

    def _handle_sf(self, arbitration_id: int, data_bytes: List[int], dlc: int):
        """Handles an ISO-TP Single Frame. Puts [PCI_byte(s), SID, data...] on response_queue."""
        pci_byte_val = data_bytes[0]
        length = pci_byte_val & 0x0F
        payload_data_start_index = 1 # Index of SID in data_bytes after this PCI

        if length == 0: # SF with length escape
            if dlc < 2:
                self._log(f"Error: ISO-TP SF (LL) DLC {dlc} < 2 for ID {arbitration_id:X}. Discarding.")
                self._reset_isotp_state(); return
            length = data_bytes[1] # Actual length of diagnostic payload (SID + data)
            payload_data_start_index = 2 # Index of SID in data_bytes after PCI (0x00) and length byte
            if length == 0:
                self._log(f"Error: ISO-TP SF (LL) actual diagnostic payload length is 0 for ID {arbitration_id:X}. Discarding.")
                self._reset_isotp_state(); return
        elif length > 7: # For standard CAN (non-FD SF PCI length cannot be > 7)
            self._log(f"Error: Invalid ISO-TP SF PCI length {length} (PCI: {pci_byte_val:02X}) for ID {arbitration_id:X}. Discarding.")
            self._reset_isotp_state(); return

        # Minimum DLC needed for the PCI bytes + declared diagnostic payload length
        expected_min_dlc_for_pci_and_payload = length + payload_data_start_index

        if dlc < expected_min_dlc_for_pci_and_payload:
            self._log(f"Error: ISO-TP SF DLC {dlc} is less than required {expected_min_dlc_for_pci_and_payload} for declared diag payload length {length} (PCI: {pci_byte_val:02X}) for ID {arbitration_id:X}. Discarding.")
            self._reset_isotp_state(); return

        # Number of actual diagnostic payload bytes available in this CAN frame
        actual_diagnostic_payload_bytes_in_frame = dlc - payload_data_start_index
        # We should only take 'length' bytes as declared in PCI for the diagnostic payload
        diagnostic_payload_to_extract_count = min(length, actual_diagnostic_payload_bytes_in_frame)

        # diagnostic_payload should be [SID, data_byte1, data_byte2,...]
        diagnostic_payload_content = data_bytes[payload_data_start_index : payload_data_start_index + diagnostic_payload_to_extract_count]

        if not diagnostic_payload_content:
            self._log(f"SF Warning: Empty diagnostic payload extracted for ID {arbitration_id:X}, PCI: {pci_byte_val:02X}, DeclaredLen: {length}")
            self._reset_isotp_state(); return # Or handle as error appropriately

        # Construct response_entry WITH PCI information, as per original logic
        if payload_data_start_index == 1: # Normal SF (PCI byte was data_bytes[0])
            response_entry = [pci_byte_val] + diagnostic_payload_content
        else: # SF with length escape (PCI bytes were data_bytes[0] and data_bytes[1])
            response_entry = [data_bytes[0], data_bytes[1]] + diagnostic_payload_content

        self.response_queue.put(response_entry)
        # self._log(f"SF Processed: ID={arbitration_id:X}, Data on Q: {response_entry}")
        self._reset_isotp_state() # SF is a complete message

    def _handle_ff(self, arbitration_id: int, data_bytes: List[int], dlc: int):
        """Handles an ISO-TP First Frame. Assumes isotp_lock is held."""
        if dlc < 2: # FF needs at least 2 bytes for PCI (type+len_high, len_low)
            self._log(f"Error: UDS First Frame DLC {dlc} < 2 for ID {arbitration_id:X}. Resetting ISO-TP.")
            self._reset_isotp_state(); return

        pci_byte_ff_val = data_bytes[0] # Contains FF type (0x1) and high nibble of length
        len_high_nibble = pci_byte_ff_val & 0x0F
        self._isotp_expected_len = (len_high_nibble << 8) + data_bytes[1] # Full expected *diagnostic* payload length
        diagnostic_payload_start_index = 2 # Diagnostic payload in FF starts after the two PCI bytes

        if self._isotp_expected_len == 0 or self._isotp_expected_len > 4095: # ISO-TP max length
            self._log(f"Error: Invalid or unsupported UDS First Frame length {self._isotp_expected_len} for ID {arbitration_id:X}. Resetting ISO-TP.")
            self._reset_isotp_state(); return

        if dlc < diagnostic_payload_start_index: # DLC too short to even contain the FF PCI
            self._log(f"Error: UDS First Frame DLC {dlc} is less than header size {diagnostic_payload_start_index} for ID {arbitration_id:X}. Resetting ISO-TP.")
            self._reset_isotp_state(); return

        # Extract initial part of diagnostic payload from the First Frame
        self._isotp_buffer = data_bytes[diagnostic_payload_start_index : dlc]

        if len(self._isotp_buffer) >= self._isotp_expected_len: # Entire message in FF
            final_diagnostic_payload = self._isotp_buffer[:self._isotp_expected_len]
            # Queue format: [ff_pci_byte, len_low_byte, SID, data...]
            response_entry = [pci_byte_ff_val, data_bytes[1]] + final_diagnostic_payload
            if final_diagnostic_payload : self.response_queue.put(response_entry)
            # else: self._log(f"FF (Complete) Warning: Empty final diagnostic payload for ID {arbitration_id:X}")
            self._reset_isotp_state()
        else: # Prepare for Consecutive Frames
            self._isotp_frame_index = 1
            self._isotp_state = ISOTPState.WAIT_CF
            self._isotp_target_id = arbitration_id
            self._isotp_flow_control_id = arbitration_id # ECU's response ID that sent the FF
            self._isotp_frames_since_fc = 0
            # Default BS=0 (send all), STmin=0 (no delay) for our initial FC response
            self._send_flow_control(flow_status=FC_STATUS_CTS, block_size=0, st_min_ms=0)
            # self._log(f"FF Processed, sent FC, waiting for CFs: ID={arbitration_id:X}, ExpLen={self._isotp_expected_len}, Buffered={len(self._isotp_buffer)}")

    def _handle_cf(self, arbitration_id: int, data_bytes: List[int], dlc: int):
        """Handles an ISO-TP Consecutive Frame. Assumes isotp_lock is held."""
        if dlc < 1: # CF needs at least 1 byte for PCI (type + index)
            self._log(f"Error: UDS Consecutive Frame DLC {dlc} < 1 for ID {arbitration_id:X}. Resetting ISO-TP.")
            self._reset_isotp_state(); return

        pci_byte_cf = data_bytes[0]
        current_index = pci_byte_cf & 0x0F
        expected_wrapped_index = self._isotp_frame_index % 16

        if current_index != expected_wrapped_index:
            self._log(f"Error: UDS Consecutive Frame index mismatch for ID {arbitration_id:X}. Expected {expected_wrapped_index}, got {current_index}. Resetting ISO-TP.")
            self._reset_isotp_state(); return

        # Append diagnostic payload data from CF (byte 1 onwards)
        self._isotp_buffer.extend(data_bytes[1 : dlc])
        self._isotp_frame_index += 1
        self._isotp_frames_since_fc += 1

        if len(self._isotp_buffer) >= self._isotp_expected_len: # Full message received
            final_diagnostic_payload = self._isotp_buffer[:self._isotp_expected_len]

            # Reconstruct FF PCI bytes to prepend to the assembled payload for queue consistency (Original logic)
            len_high_nibble = (self._isotp_expected_len >> 8) & 0x0F
            ff_pci_reconstructed = (PCI_TYPE_FF << 4) | len_high_nibble
            len_low_byte_reconstructed = self._isotp_expected_len & 0xFF
            # Queue format: [ff_pci_byte, len_low_byte, SID, data...]
            response_entry = [ff_pci_reconstructed, len_low_byte_reconstructed] + final_diagnostic_payload

            if final_diagnostic_payload: self.response_queue.put(response_entry)
            # else: self._log(f"CF (Complete) Warning: Empty final diagnostic payload for ID {arbitration_id:X}")
            self._reset_isotp_state()
        elif self._isotp_block_size > 0 and self._isotp_frames_since_fc >= self._isotp_block_size:
            # We (receiver) have received a full block, send another FC
            self._isotp_frames_since_fc = 0
            st_min_ms_int = int(self._isotp_stmin * 1000) # Use STmin set by sender's FC
            self._send_flow_control(flow_status=FC_STATUS_CTS, block_size=self._isotp_block_size, st_min_ms=st_min_ms_int)
            # self._log(f"CF Processed, sent next FC: ID={arbitration_id:X}, Buffered={len(self._isotp_buffer)}")

    def _handle_fc(self, arbitration_id: int, data_bytes: List[int]):
        """
        Handles an incoming ISO-TP Flow Control frame. Assumes isotp_lock is held.
        This is relevant if *we* are sending a multi-frame message and receive an FC from the ECU,
        OR if the ECU (sender) sends an FC (e.g., WAIT) while we are receiving CFs.
        """
        if len(data_bytes) < 3: # FC needs PCI, BS, STmin
            self._log(f"Warning: Short Flow Control frame received from {arbitration_id:X}. Length {len(data_bytes)}. Ignoring.")
            return

        pci_byte_fc = data_bytes[0]
        flow_status = pci_byte_fc & 0x0F
        block_size_rcvd = data_bytes[1]
        st_min_raw_rcvd = data_bytes[2]

        st_min_ms = 0.0
        if 0 <= st_min_raw_rcvd <= 0x7F: st_min_ms = float(st_min_raw_rcvd)
        elif 0xF1 <= st_min_raw_rcvd <= 0xF9: st_min_ms = (st_min_raw_rcvd - 0xF0) * 0.1
        else:
            self._log(f"Warning: Received FC with STmin raw value {st_min_raw_rcvd:02X} (reserved/invalid). Using 127ms default.")
            st_min_ms = 127.0

        st_min_sec = st_min_ms / 1000.0
        flow_status_str = {FC_STATUS_CTS: "CTS", FC_STATUS_WT: "WAIT", FC_STATUS_OVFLW: "OVFLW"}.get(flow_status, f"?({flow_status})")
        # self._log(f"Received Flow Control from {arbitration_id:X}: FS={flow_status_str}, BS={block_size_rcvd}, STmin_raw={st_min_raw_rcvd:02X} ({st_min_ms:.1f}ms)")

        if self._isotp_state == ISOTPState.WAIT_CF and arbitration_id == self._isotp_target_id:
            # We are RECEIVING, and sender (ECU) sent an FC (e.g. WAIT or to update params)
            if flow_status == FC_STATUS_CTS:
                # Sender is confirming its parameters, or re-sending CTS. Store them.
                self._isotp_block_size = block_size_rcvd # How many CFs sender will send before next FC from us
                self._isotp_stmin = st_min_sec         # Min time sender wants between our FCs (not directly used by us as receiver here)
                                                      # More accurately, STmin in an FC from sender to us (receiver)
                                                      # tells *us* the minimum time *they* will wait between *their CFs*.
                                                      # This should be used to time our processing/FC responses if needed,
                                                      # but typically the sender just sends based on our FC.
                                                      # Let's assume this STmin from ECU's FC is for *their* CF transmission rate.
                self._isotp_frames_since_fc = 0 # Reset counter if they are confirming params
                # self._log(f"  -> Sender {arbitration_id:X} FC updated our receiver state: Their_BS={block_size_rcvd}, Their_CF_STmin={st_min_sec:.3f}s")
            elif flow_status == FC_STATUS_WT:
                self._log(f"Received WAIT Flow Control from sender {arbitration_id:X}. Pausing reception logic may be needed (currently, listener continues).")
                # TODO: Implement actual wait logic if required (e.g., set a timer before expecting more CFs or re-sending our FC after a timeout)
            elif flow_status == FC_STATUS_OVFLW:
                self._log(f"Error: Sender {arbitration_id:X} reported OVFLW (Overflow). Resetting ISO-TP state.")
                self._reset_isotp_state()

        elif self._isotp_state == ISOTPState.WAIT_FC: # We are SENDING, and this is the FC from the receiver (ECU)
            # self._log(f"FC received while in WAIT_FC (we are sender). FS={flow_status_str}, BS={block_size_rcvd}, STmin={st_min_sec:.3f}s for ECU {arbitration_id:X}")
            if flow_status == FC_STATUS_CTS:
                self._isotp_block_size = block_size_rcvd # How many CFs we can send before next FC from ECU
                self._isotp_stmin = st_min_sec         # Min time we must wait between our CFs
                self._isotp_frames_since_fc = 0       # Reset counter for CFs we've sent in current block
                self._isotp_state = ISOTPState.IDLE # Or a new state like SENDING_CFS. For now, IDLE, send loop will handle it.
                # The actual sending of next block of CFs would be handled by the sending logic, not here.
            elif flow_status == FC_STATUS_WT:
                self._log(f"Receiver {arbitration_id:X} sent WAIT. We (sender) must pause sending CFs.")
                # TODO: Implement logic in the sending part to handle WAIT (e.g., timer, retry FC)
            elif flow_status == FC_STATUS_OVFLW:
                self._log(f"Error: Receiver {arbitration_id:X} (ECU) reported OVFLW. Aborting send operation.")
                self._reset_isotp_state() # Stop sending
        # else:
            # self._log(f"Warning: Received Flow Control from {arbitration_id:X} in unexpected ISO-TP state ({self._isotp_state.name}). Ignoring.")


    def register_live_dashboard_processor(self, processor: Optional[ILiveDataProcessor]):
        """Registers or unregisters the live dashboard data processor."""
        if processor is None:
            if self.live_dashboard_processor:
                self._log("Unregistering live dashboard processor.")
            self.live_dashboard_processor = None
        elif hasattr(processor, 'TARGET_IDS') and callable(getattr(processor, 'process_message', None)):
            target_ids_str = ", ".join(f"{tid:X}" for tid in processor.TARGET_IDS) if processor.TARGET_IDS else "All (if supported)"
            self._log(f"Registering live dashboard processor targeting IDs: {target_ids_str}")
            self.live_dashboard_processor = processor
        else:
            self._log("Error: Invalid live dashboard processor passed (missing TARGET_IDS or process_message).")
            self.live_dashboard_processor = None

    # register_expert_raw_processor
    def register_expert_raw_processor(self, processor: Optional[ICanRawMessageProcessor]):
        """Registers or unregisters a raw CAN message processor for the expert tab."""
        if processor:
            self._log(f"Registering expert raw CAN processor: {type(processor).__name__}")
        else:
            if self.expert_raw_processor:
                self._log(f"Unregistering expert raw CAN processor: {type(self.expert_raw_processor).__name__}")
        self.expert_raw_processor = processor

    # send_custom_can_message
    def send_custom_can_message(self, arbitration_id: int, data: Union[List[int], bytes], is_extended: bool = False, is_remote: bool = False) -> bool:
        """
        Sends a custom CAN message. Public method for features like CAN Expert Tab.
        """
        if not self.is_connected or not self.bus:
            self._log("Error: Cannot send custom CAN message, not connected.")
            return False
        # _send_can_message already logs the attempt.
        return self._send_can_message(arbitration_id, data, is_extended, is_remote)