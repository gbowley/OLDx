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
# Define which IDs strictly use ISO-TP multi-frame logic
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


    def _send_can_message(self, arbitration_id: int, data: Any, is_extended: bool = False, is_remote: bool = False) -> bool:
        """
        Internal method to send a single CAN message.
        Handles data type conversion and padding.
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

            # For remote frames, the data field is typically not used for sending, 
            # and the DLC indicates the expected length of the reply.
            # python-can's Message object handles this when is_remote_frame=True.
            # If is_remote is true, data_bytes might be empty, and DLC should reflect that or the expected length.
            # Current logic uses len(data_bytes) for DLC. This is fine for data frames.
            # For remote frames, if data_bytes is empty, DLC will be 0. If data_bytes has content,
            # python-can might ignore the data part for actual transmission if is_remote_frame=True.
            # Let's ensure DLC is appropriate for RTR. Typically, DLC in an RTR frame *requests* that many bytes.
            
            actual_dlc = len(data_bytes)
            if is_remote:
                # If sending an RTR frame, the data field isn't transmitted.
                # The DLC in the RTR frame indicates the number of bytes requested from the remote node.
                # If the user supplied data for an RTR frame, we use its length as the requested DLC.
                # If no data was supplied, DLC will be 0 (requesting 0 bytes, or sometimes interpreted as requesting max).
                # The 'data' field of the can.Message object will be ignored by the bus if is_remote_frame=True.
                pass # actual_dlc is already len(data_bytes)

            if actual_dlc > 8:
                 self._log(f"Error: CAN data length ({actual_dlc}) for DLC exceeds 8 bytes. ID={arbitration_id:03X}")
                 return False

            # Padding for can.Message object (some backends might expect 8 bytes in the data attribute,
            # but DLC is the important part for the actual CAN frame on the bus).
            if len(data_bytes) < 8:
                padded_data_for_msg_obj = data_bytes + bytes([0xAA] * (8 - len(data_bytes)))
            else:
                padded_data_for_msg_obj = data_bytes

            message = can.Message(
                arbitration_id=arbitration_id,
                data=padded_data_for_msg_obj, # Data to be sent or ignored if RTR
                is_extended_id=is_extended,
                is_remote_frame=is_remote,      # SET THE RTR FLAG HERE
                is_fd=False, 
                dlc=actual_dlc                  # Set correct DLC
            )
            self.bus.send(message, timeout=0.2) 
            
            # Log the sent frame details
            log_data_str = data_bytes.hex().upper() if not is_remote else "(RTR Frame)"
            self._log(f"Sent: ID={arbitration_id:03X} DLC={actual_dlc} Data={log_data_str} Ext={is_extended} RTR={is_remote}") # MODIFIED Log
            return True
        
        except ValueError as ve: 
            self._log(f"Data Error sending CAN message (ID: {arbitration_id:03X}): {ve}")
        except can.CanError as e: 
            self._log(f"CAN Bus Error sending message (ID: {arbitration_id:03X}): {e}")
        except Exception as e: 
            self._log(f"Unexpected error sending CAN message (ID: {arbitration_id:03X}): {e}")
        return False

        # --- Resolve Command ---
        resolved_req_id: Optional[int] = req_id
        resolved_data: Optional[Union[List[int], bytes]] = data
        resolved_is_extended: bool = is_extended
        request_service_id: Optional[int] = None # The SID we are sending in our request

        if resolved_req_id is None or resolved_data is None: # If not fully specified, look up or parse
            if command_name.startswith('p'): # Performance DID request, e.g., "p0100"
                 try:
                     did_hex = command_name[1:]
                     assert len(did_hex) == 4 # Ensure DID is 2 bytes (4 hex chars)
                     did_int = int(did_hex, 16)
                     resolved_req_id = UDS_REQUEST_ID
                     resolved_data = [0x03, 0x22, (did_int >> 8) & 0xFF, did_int & 0xFF] # Mode 22, DID hi, DID lo
                     request_service_id = 0x22
                 except (ValueError, AssertionError, Exception) as e:
                     self._log(f"Error: Invalid performance command format '{command_name}': {e}")
                     return False, None
            elif command_name.startswith('s'): # Raw send command, e.g., "s07E002010D"
                try:
                    assert len(command_name) >= 7 # 's' + 4 ID hex + at least 2 data hex
                    raw_id_hex = command_name[1:5]
                    raw_data_hex = command_name[5:]
                    assert len(raw_data_hex) % 2 == 0 # Data hex must be even length
                    resolved_req_id = int(raw_id_hex, 16)
                    resolved_data = bytes.fromhex(raw_data_hex)
                    # Determine SID from data if possible (usually byte 1 or 2 after PCI)
                    if len(resolved_data) > 1: request_service_id = resolved_data[1] # Guessing SID is at index 1
                except (ValueError, AssertionError, Exception) as e:
                    self._log(f"Error parsing raw send command '{command_name}': {e}")
                    return False, None
            else: # Lookup in predefined COMMANDS
                command_tuple = COMMANDS.get(command_name)
                if command_tuple is None:
                    # Check if it's a command that doesn't send a CAN message (e.g. local action)
                    if command_name in COMMANDS and COMMANDS[command_name] is None:
                        self._log(f"Executing local action (no CAN send): {command_name}")
                        # Handle local actions like 'monitorAllStart', 'enableFlowControl' if needed here
                        return True, None # Or specific return based on action
                    else:
                        self._log(f"Error: Command '{command_name}' not recognized or not configured for sending.")
                        return False, None
                resolved_req_id, data_list = command_tuple
                resolved_data = bytes(data_list) # Ensure it's bytes
                # Determine SID from data_list (usually index 1 after length/PCI byte)
                if len(data_list) > 1: request_service_id = data_list[1]

        if resolved_req_id is None or resolved_data is None: # Should be resolved by now
            self._log(f"Internal Error: Could not determine CAN message data for command '{command_name}'.")
            return False, None

        # --- Prepare for Response ---
        # Clear any stale messages from the response queue before sending new command
        while not self.response_queue.empty():
            try:
                stale_msg = self.response_queue.get_nowait()
                self._log(f"Cleared stale message from response queue: {stale_msg}")
            except queue.Empty:
                break # Queue is empty

        with self._isotp_lock: # Ensure thread-safe access to ISO-TP state
            self._reset_isotp_state() # Reset ISO-TP state for new transaction
            # Set target ID for ISO-TP responses if applicable
            if resolved_req_id in UDS_RESPONSE_IDS_FOR_ISOTP or resolved_req_id == UDS_REQUEST_ID: # Common UDS case
                 self._isotp_target_id = resolved_req_id + 8 # Target the corresponding UDS response ID (e.g., 0x7E0 -> 0x7E8)

        # --- Activate Raw Logging & Send Command ---
        self._activate_raw_diag_logging() # Start raw logging for this transaction
        if not self._send_can_message(resolved_req_id, resolved_data, resolved_is_extended):
            self._deactivate_raw_diag_logging() # Stop raw logging if send failed
            return False, None

        # --- Wait for Response ---
        start_time = time.monotonic()
        response_received: Optional[List[int]] = None
        success_flag = False
        # Determine if this was a KWP request based on the request ID (e.g., ABS_REQUEST_ID)
        is_kwp_request = resolved_req_id == ABS_REQUEST_ID

        while True:
            current_time = time.monotonic()
            if current_time - start_time > timeout:
                self._log(f"Timeout ({timeout}s) waiting for response to command '{command_name}' (ReqID: {resolved_req_id:X})")
                with self._isotp_lock: self._reset_isotp_state() # Reset ISO-TP state on timeout
                success_flag = False; response_received = None
                break # Exit loop on timeout

            try:
                # Get processed response from the response_queue (populated by _parse_incoming_message)
                response_data = self.response_queue.get(block=True, timeout=0.1) # Small timeout for queue get

                # --- Determine Service ID Index based on protocol ---
                service_id_index = -1 # Index within response_data where SID is expected
                response_format_type = "Unknown"
                actual_service_id = None

                if not response_data: # Should not happen if queue put valid data
                    self._log(f"Received empty response fragment from queue. Continuing wait.")
                    continue

                if is_kwp_request:
                    # For KWP, _parse_incoming_message puts [SID, Payload...] into response_queue
                    service_id_index = 0
                    response_format_type = "KWP"
                    if len(response_data) > service_id_index:
                        actual_service_id = response_data[service_id_index]
                    else: # Should not happen
                         self._log(f"Received invalid/short KWP response fragment from queue: {response_data}. Continuing wait.")
                         continue
                else: # UDS/ISO-TP path
                    # _parse_incoming_message puts [pci_byte(s), SID, Payload...] for UDS
                    first_byte = response_data[0]
                    pci_type = (first_byte >> 4) & 0x0F # Get PCI type from first byte

                    if pci_type == PCI_TYPE_FF: # UDS MF: [ff_pci, len_low, SID, ...]
                        if len(response_data) >= 3: service_id_index = 2; response_format_type = "UDS_MF"
                    elif pci_type == PCI_TYPE_SF: # UDS SF: [pci_byte(incl.len), SID, ...]
                        if len(response_data) >= 2: service_id_index = 1; response_format_type = "UDS_SF"
                    elif first_byte == 0x00 and len(response_data) >= 3: # UDS SF length escape [0x00, Len, SID, ...]
                        # This indicates the SF PCI was 0x00, and the actual length followed.
                        service_id_index = 2; response_format_type = "UDS_SF_ESC"
                    # Note: CF frames are assembled and only the final payload (starting with FF PCI) is put on queue.

                    if service_id_index != -1: # If SID index was determined
                         actual_service_id = response_data[service_id_index]
                    else: # Could not determine SID for UDS response
                         self._log(f"Received ambiguous/short UDS response from queue: {response_data}. Continuing wait.")
                         continue

                if actual_service_id is None: # Should have been set if logic above is correct
                     self._log(f"Could not determine actual_service_id for response: {response_data}. Format guess: {response_format_type}. Continuing wait.")
                     continue

                # --- Validate Response ---
                is_negative_response = False
                nrc = 0 # Negative Response Code
                req_serv_echo = 0 # Service ID echoed in the NRC response

                if actual_service_id == 0x7F: # Negative Response SID
                    is_negative_response = True
                    if is_kwp_request:
                        # KWP NRC format from queue: [0x7F, req_sid_echo, nrc, ...]
                        req_serv_echo = response_data[1] if len(response_data) > 1 else 0
                        nrc = response_data[2] if len(response_data) > 2 else 0
                    else: # UDS NRC
                        # UDS NRC format from queue: [pci(s), 0x7F, req_sid_echo, nrc, ...]
                        # SID echo is at service_id_index + 1, NRC at service_id_index + 2
                        sid_echo_index = service_id_index + 1
                        nrc_index = service_id_index + 2
                        if len(response_data) > nrc_index:
                            req_serv_echo = response_data[sid_echo_index]
                            nrc = response_data[nrc_index]
                        else: # Cannot reliably extract NRC from short UDS NRC response
                            self._log(f"Warning: Short UDS NRC response received: {response_data}")
                            req_serv_echo = request_service_id if request_service_id is not None else 0xFF # Best guess
                            nrc = 0 # Unknown NRC

                if is_negative_response:
                    # Check if NRC is for the service we just sent
                    if request_service_id is None or req_serv_echo == request_service_id:
                         self._log(f"Received NRC: {nrc:02X} ({decode_nrc(nrc)}) for Service ${req_serv_echo:02X} (Command: {command_name}) Format: {response_format_type}")
                         with self._isotp_lock: self._reset_isotp_state() # Reset ISO-TP state
                         success_flag = False # NRC means command was not successful in the ECU's view
                         response_received = response_data # Keep NRC response data
                         break # Exit loop, NRC received for our command
                    else: # NRC for a different service (e.g., late response)
                         self._log(f"Ignoring late/mismatched NRC: {nrc:02X} for Service ${req_serv_echo:02X} while waiting for Service ${request_service_id if request_service_id else 'Any'} (Cmd: {command_name})")
                         continue # Ignore this NRC and continue waiting

                # Check for Positive Response Match (if not an NRC)
                if expected_response_service_id is not None: # If we expect a specific positive SID
                    if actual_service_id == expected_response_service_id:
                        # self._log(f"Received expected positive response (SID: {actual_service_id:02X}, Format: {response_format_type}) for {command_name}")
                        success_flag = True; response_received = response_data
                        break # Correct positive response received
                    else: # Positive response, but not the SID we expected
                        log_data_hex = bytes(response_data).hex().upper()
                        self._log(f"Ignoring mismatched positive response (Expected SID: {expected_response_service_id:02X}, Got SID: {actual_service_id:02X}, Format: {response_format_type}, Data: {log_data_hex}) while waiting for {command_name}")
                        continue # Ignore this response and continue waiting
                else: # Accept first positive response if no specific SID expected
                    # self._log(f"Received first positive response (SID: {actual_service_id:02X}, Format: {response_format_type}) for {command_name}")
                    success_flag = True; response_received = response_data
                    break # First positive response is acceptable

            except queue.Empty:
                continue # Normal timeout from response_queue.get(), loop again
            except Exception as e:
                self._log(f"Error processing response queue for command '{command_name}': {e}\n{traceback.format_exc()}")
                success_flag = False; response_received = None
                break # Exit loop on unexpected error

        self._deactivate_raw_diag_logging() # Stop raw logging after transaction
        return success_flag, response_received


    def _send_flow_control(self, flow_status: int = FC_STATUS_CTS, block_size: int = 0, st_min_ms: int = 0):
        """Sends an ISO-TP Flow Control frame."""
        if self._isotp_flow_control_id is None: # This is the ID of the ECU that sent the FF
            self._log("Error: Cannot send Flow Control, flow control target ID (ECU's response ID) not set.")
            return

        # Determine destination ID for FC (usually the ECU's request ID = ECU's response ID - 8)
        # Example: If ECU responded on 0x7E8 (FF), we send FC to 0x7E0.
        if 0x7E8 <= self._isotp_flow_control_id <= 0x7EF: # Common UDS physical addressing range
            fc_destination_id = self._isotp_flow_control_id - 8
        elif self._isotp_flow_control_id == TCU_RESPONSE_ID: # Specific handling for TCU if needed
            fc_destination_id = TCU_REQUEST_ID
        # Add other specific mappings if ECU uses non-standard request/response ID pairs for ISO-TP
        else:
            # Avoid sending FC for non-standard or potentially KWP IDs unless explicitly handled
            self._log(f"Warning: Suppressing Flow Control frame intended for non-standard response ID {self._isotp_flow_control_id:X}.")
            return

        # Double check we are not sending FC to a known KWP request ID (which wouldn't expect it)
        if fc_destination_id == ABS_REQUEST_ID: # ABS uses KWP, doesn't expect ISO-TP FC
            self._log(f"Warning: Suppressing Flow Control frame intended for KWP request ID {fc_destination_id:X}.")
            return

        # Encode STmin (Separation Time Minimum)
        st_min_can_byte = 0x00 # Default to 0ms
        if 0 <= st_min_ms <= 127: # 0-127 ms
            st_min_can_byte = st_min_ms
        elif 100 <= st_min_ms <= 900 and st_min_ms % 100 == 0 : # 100-900 us range (0xF1-0xF9)
            st_min_can_byte = 0xF0 + (st_min_ms // 100)
        else: # Value out of standard range or not a multiple of 100us for F1-F9
            self._log(f"Warning: STmin {st_min_ms}ms out of standard ISO-TP range or granularity, using 0ms for FC.")
            st_min_can_byte = 0x00 # Fallback to 0ms

        fc_pci = (PCI_TYPE_FC << 4) | (flow_status & 0x0F) # PCI: Type=FC, FS=flow_status
        fc_data = [fc_pci, block_size & 0xFF, st_min_can_byte] # FC frame: PCI, BS, STmin

        flow_status_str = {FC_STATUS_CTS: "CTS", FC_STATUS_WT: "WAIT", FC_STATUS_OVFLW: "OVFLW"}.get(flow_status, f"?({flow_status})")
        self._log(f"Sending Flow Control ({flow_status_str}, BS={block_size}, STmin_raw={st_min_can_byte:02X} ({st_min_ms}ms)) to ID {fc_destination_id:03X}")
        self._send_can_message(fc_destination_id, fc_data)


    def _reset_isotp_state(self):
        """Resets ISO-TP state variables. Assumes lock is held if called from multiple threads."""
        # self._log("Resetting ISO-TP state") # Optional: for debugging state changes
        if self._isotp_state != ISOTPState.IDLE:
            pass # Could log previous state if needed for debugging
        self._isotp_state = ISOTPState.IDLE
        self._isotp_target_id = None
        self._isotp_buffer = []
        self._isotp_expected_len = 0
        self._isotp_frame_index = 0
        self._isotp_flow_control_id = None
        self._isotp_block_size = 0
        self._isotp_stmin = 0.0
        self._isotp_frames_since_fc = 0


    def _parse_incoming_message(self, msg: can.Message):
        """
        Parses incoming diagnostic messages from the rx_queue.
        Handles ISO-TP assembly for UDS messages and direct passthrough for KWP.
        Puts fully assembled messages or KWP payloads onto self.response_queue.
        """
        if not hasattr(msg, 'data') or not msg.data or msg.dlc == 0:
            return # Ignore messages with no data

        data_bytes = list(msg.data) # Convert to list for easier manipulation
        arbitration_id = msg.arbitration_id

        try:
            # --- Handle non-UDS (e.g., KWP) responses first ---
            if arbitration_id not in UDS_RESPONSE_IDS_FOR_ISOTP: # Check if ID is NOT for ISO-TP
                 if arbitration_id == ABS_RESPONSE_ID: # KWP response from ABS
                     # For KWP, we expect the payload to start after a potential length/format byte.
                     # Assuming the first byte of data_bytes might be a length or format indicator not part of SID/payload.
                     # The actual SID and data follow.
                     # Example KWP response: [Len, SID, Data...] or [Format, SID, Data...]
                     # We pass [SID, Data...] to the response queue.
                     if msg.dlc >= 2: # KWP response must have at least SID byte (after a potential first byte)
                        # Assuming SID is at data_bytes[1] for KWP messages from ABS_RESPONSE_ID
                        kwp_payload_with_sid = data_bytes[1:msg.dlc] # Get payload from byte 1 up to DLC
                        if kwp_payload_with_sid: # Ensure there's something to put
                            self.response_queue.put(kwp_payload_with_sid)
                        # else: # Optional: log if KWP payload part is empty after slicing
                        #    self._log(f"Warning: KWP message from {arbitration_id:X} has empty payload after slicing. DLC={msg.dlc}, Data={data_bytes}")
                     # else: # Optional: log if KWP response too short to contain SID + data
                     #    self._log(f"Warning: Received KWP message from {arbitration_id:X} too short (DLC={msg.dlc}) to contain SID and data.")
                 else:
                     # Could be other non-ISO-TP diagnostic messages or broadcast data.
                     # This function is primarily for diagnostic responses for send_command.
                     pass
                 return # Stop processing for non-ISO-TP IDs in this function

            # --- ISO-TP Logic for UDS IDs (e.g., UDS_RESPONSE_ID, TCU_RESPONSE_ID) ---
            pci_byte = data_bytes[0]
            frame_type = (pci_byte >> 4) & 0x0F # Get PCI type (SF, FF, CF, FC)

            with self._isotp_lock: # Ensure thread-safe access to ISO-TP state
                if self._isotp_state == ISOTPState.IDLE:
                    if frame_type == PCI_TYPE_SF: # Single Frame
                        self._handle_sf(arbitration_id, data_bytes, msg.dlc)
                    elif frame_type == PCI_TYPE_FF: # First Frame
                        self._handle_ff(arbitration_id, data_bytes, msg.dlc)
                    elif frame_type == PCI_TYPE_CF: # Consecutive Frame (unexpected in IDLE)
                         self._log(f"Warning: Received unexpected Consecutive Frame from ID {arbitration_id:X} in IDLE state. Resetting ISO-TP.")
                         self._reset_isotp_state() # Reset state
                    elif frame_type == PCI_TYPE_FC: # Flow Control (unexpected in IDLE from ECU)
                         fs = pci_byte & 0x0F; flow_status_str = {0: "CTS", 1: "WAIT", 2: "OVFLW"}.get(fs, f"?({fs})")
                         self._log(f"Warning: Received unexpected Flow Control from ID {arbitration_id:X} in IDLE state. FS={flow_status_str}. Ignoring.")
                         # No state reset needed, just ignore it.

                elif self._isotp_state == ISOTPState.WAIT_CF: # Waiting for Consecutive Frame
                    if arbitration_id != self._isotp_target_id: # Message from unexpected ID
                        # self._log(f"Debug: Ignoring message from {arbitration_id:X}, currently waiting for CF from {self._isotp_target_id:X}")
                        return # Ignore messages from other IDs while assembling

                    if frame_type == PCI_TYPE_CF: # Expected Consecutive Frame
                        self._handle_cf(arbitration_id, data_bytes, msg.dlc)
                    elif frame_type == PCI_TYPE_FC: # Flow Control (e.g., sender sends WAIT)
                         # This can happen if the sender (ECU) sends a WAIT FC frame.
                         self._log(f"Received Flow Control from {arbitration_id:X} while waiting for CF. Handling FC.")
                         self._handle_fc(arbitration_id, data_bytes) # Process the FC frame
                    else: # SF or FF received while waiting for CF (error condition)
                        self._log(f"Error: Expected Consecutive Frame from {arbitration_id:X}, but received frame type {frame_type:X}. Resetting ISO-TP state.")
                        self._reset_isotp_state() # Reset state due to protocol error
                        # Attempt to process the new frame if it's a start frame (SF or FF)
                        if frame_type == PCI_TYPE_SF: self._handle_sf(arbitration_id, data_bytes, msg.dlc)
                        elif frame_type == PCI_TYPE_FF: self._handle_ff(arbitration_id, data_bytes, msg.dlc)
                # Note: ISOTPState.WAIT_FC is typically used when *we* are the SENDER of a multi-frame message
                # and are waiting for an FC from the ECU. This function handles *incoming* messages.
                # If we receive an FC while in WAIT_FC (meaning we are sending), _handle_fc would be called.

        except IndexError as e: # Error accessing data_bytes elements
             self._log(f"Error parsing incoming message (IndexError): {e}, Data: {bytes(msg.data).hex()}, ID: {arbitration_id:X}")
             with self._isotp_lock: self._reset_isotp_state() # Reset ISO-TP state on error
        except Exception as e: # Other unexpected errors
             self._log(f"Unexpected error parsing incoming message: {type(e).__name__}: {e}, Data: {bytes(msg.data).hex()}, ID: {arbitration_id:X}")
             # traceback.print_exc() # For debugging
             with self._isotp_lock: self._reset_isotp_state() # Reset ISO-TP state on error


    def _handle_sf(self, arbitration_id: int, data_bytes: List[int], dlc: int):
        """Handles an ISO-TP Single Frame. Assumes isotp_lock is held."""
        pci_byte_val = data_bytes[0]
        length = pci_byte_val & 0x0F # Length is in lower nibble of first PCI byte
        payload_start_index = 1 # Payload starts after the first PCI byte

        if length == 0: # SF with length escape (length in the second byte)
            if dlc < 2: # Need at least 2 bytes for PCI (0x00) and actual length
                self._log(f"Error: UDS Single Frame (with length escape) DLC {dlc} < 2 for ID {arbitration_id:X}. Discarding.")
                return
            length = data_bytes[1] # Actual length is in the second byte
            payload_start_index = 2 # Payload starts after PCI (0x00) and length byte
            if length == 0: # Invalid: actual length cannot be 0 after escape
                self._log(f"Error: UDS Single Frame (with length escape) actual length is 0 for ID {arbitration_id:X}. Discarding.")
                return
        # Standard CAN (non-FD) SF length is 1-7 bytes.
        # python-can's Message object uses DLC for actual data length.
        # Here, 'length' is the declared payload length in PCI.
        elif length > 7: # For standard CAN, SF payload length > 7 is invalid.
            self._log(f"Error: Invalid UDS Single Frame PCI length {length} (PCI: {pci_byte_val:02X}) for non-FD CAN ID {arbitration_id:X}. Discarding.")
            return

        # Minimum DLC required for the declared payload length
        expected_dlc_for_payload = length + payload_start_index
        # Check if DLC is sufficient for the declared payload length.
        # Allow DLC=8 even if payload is shorter (due to CAN frame padding).
        if dlc < expected_dlc_for_payload and dlc != 8 : # Common case: DLC matches payload + PCI bytes
             self._log(f"Error: UDS Single Frame DLC {dlc} is less than required {expected_dlc_for_payload} for declared length {length} (PCI: {pci_byte_val:02X}) for ID {arbitration_id:X}. Discarding.")
             return

        # Extract payload, ensuring not to read past the actual DLC of the CAN frame
        # The actual number of payload bytes available is dlc - payload_start_index
        # We should only take 'length' bytes as declared in PCI, or fewer if DLC is smaller.
        actual_payload_bytes_in_frame = dlc - payload_start_index
        payload_to_extract_count = min(length, actual_payload_bytes_in_frame)

        payload = data_bytes[payload_start_index : payload_start_index + payload_to_extract_count]

        # Queue format for SF: [pci_byte(s), payload_sid, payload_data...]
        if payload_start_index == 1: # Normal SF (PCI is one byte)
            response_entry = [pci_byte_val] + payload
        else: # SF with length escape (PCI is 0x00 followed by actual length byte)
            response_entry = [0x00, length] + payload # Store 0x00 and actual length as PCI part

        self.response_queue.put(response_entry)
        # self._log(f"SF Processed: ID={arbitration_id:X}, Data on Q: {response_entry}") # Debug
        self._reset_isotp_state() # SF is a complete message


    def _handle_ff(self, arbitration_id: int, data_bytes: List[int], dlc: int):
        """Handles an ISO-TP First Frame. Assumes isotp_lock is held."""
        if dlc < 2: # FF needs at least 2 bytes for PCI (type+len_high, len_low)
            self._log(f"Error: UDS First Frame DLC {dlc} < 2 for ID {arbitration_id:X}. Resetting ISO-TP.")
            self._reset_isotp_state()
            return

        pci_byte_ff = data_bytes[0] # Contains FF type (0x1) and high nibble of length
        len_high_nibble = pci_byte_ff & 0x0F
        self._isotp_expected_len = (len_high_nibble << 8) + data_bytes[1] # Full expected payload length
        payload_start_index = 2 # Payload in FF starts after the two PCI bytes

        # ISO-TP max length is 4095 (0xFFF) for a 12-bit length field
        if self._isotp_expected_len == 0 or self._isotp_expected_len > 4095:
              self._log(f"Error: Invalid or unsupported UDS First Frame length {self._isotp_expected_len} for ID {arbitration_id:X}. Resetting ISO-TP.")
              self._reset_isotp_state()
              return

        if dlc < payload_start_index: # DLC too short to even contain the FF PCI
            self._log(f"Error: UDS First Frame DLC {dlc} is less than header size {payload_start_index} for ID {arbitration_id:X}. Resetting ISO-TP.")
            self._reset_isotp_state()
            return

        # Extract initial payload data from the First Frame
        # Max 6 bytes of payload in FF for standard CAN (8 byte frame - 2 PCI bytes)
        ff_payload_len = dlc - payload_start_index
        self._isotp_buffer = data_bytes[payload_start_index : dlc] # Store initial part of payload

        # Check if FF contains the entire message (possible if <= 6 bytes)
        if len(self._isotp_buffer) >= self._isotp_expected_len:
            final_payload = self._isotp_buffer[:self._isotp_expected_len] # Truncate if buffer is longer
            # Queue format for assembled MF (same as FF structure): [ff_pci_byte, len_low_byte, SID, payload_data...]
            response_entry = [pci_byte_ff, data_bytes[1]] + final_payload
            self.response_queue.put(response_entry)
            # self._log(f"FF (Complete) Processed: ID={arbitration_id:X}, Data on Q: {response_entry}") # Debug
            self._reset_isotp_state() # Message complete
        else:
            # Prepare for Consecutive Frames
            self._isotp_frame_index = 1 # Expect CF with index 1 next
            self._isotp_state = ISOTPState.WAIT_CF
            self._isotp_target_id = arbitration_id # Expect subsequent frames from this ID
            self._isotp_flow_control_id = arbitration_id # ID of the ECU that sent the FF (used to derive FC destination)
            self._isotp_frames_since_fc = 0
            self._isotp_block_size = 0 # Default: Wait for FC from sender if they send one, or send all if BS=0 in their FC
            self._isotp_stmin = 0.0    # Default: No delay if not specified in FC

            # Send initial Flow Control (CTS) to indicate readiness for CFs
            # Block Size (BS) = 0: Send all frames without waiting for another FC from us.
            # Separation Time (STmin) = 0: No delay required between CFs from sender.
            # These are typical initial FC parameters from a receiver.
            self._send_flow_control(flow_status=FC_STATUS_CTS, block_size=0, st_min_ms=0)
            # self._log(f"FF Processed, waiting for CFs: ID={arbitration_id:X}, ExpLen={self._isotp_expected_len}, Buffered={len(self._isotp_buffer)}") # Debug


    def _handle_cf(self, arbitration_id: int, data_bytes: List[int], dlc: int):
        """Handles an ISO-TP Consecutive Frame. Assumes isotp_lock is held."""
        if dlc < 1: # CF needs at least 1 byte for PCI (type + index)
            self._log(f"Error: UDS Consecutive Frame DLC {dlc} < 1 for ID {arbitration_id:X}. Resetting ISO-TP.")
            self._reset_isotp_state()
            return

        pci_byte_cf = data_bytes[0]
        current_index = pci_byte_cf & 0x0F # Lower nibble is the frame index (0-15)
        expected_wrapped_index = self._isotp_frame_index % 16 # Wrap expected index for comparison

        if current_index != expected_wrapped_index:
            self._log(f"Error: UDS Consecutive Frame index mismatch for ID {arbitration_id:X}. Expected index {expected_wrapped_index}, got {current_index}. Resetting ISO-TP.")
            self._reset_isotp_state()
            return

        # Append payload data from CF (byte 1 onwards, up to DLC limit)
        # Max 7 bytes of payload in CF for standard CAN (8 byte frame - 1 PCI byte)
        payload_in_cf = data_bytes[1 : dlc]
        self._isotp_buffer.extend(payload_in_cf)
        self._isotp_frame_index += 1
        self._isotp_frames_since_fc += 1

        # Check if the full message is received
        if len(self._isotp_buffer) >= self._isotp_expected_len:
            final_payload = self._isotp_buffer[:self._isotp_expected_len] # Truncate if buffer is longer
            # Reconstruct the FF PCI and length bytes for consistency in queue format
            # This makes parsing in send_command easier as it always expects FF-like structure for MF.
            len_high_nibble = (self._isotp_expected_len >> 8) & 0x0F
            len_low_byte = self._isotp_expected_len & 0xFF
            reconstructed_ff_pci = (PCI_TYPE_FF << 4) | len_high_nibble # PCI type FF + high nibble of total length
            # Queue format: [reconstructed_ff_pci, len_low_byte, SID, payload_data...]
            response_entry = [reconstructed_ff_pci, len_low_byte] + final_payload
            self.response_queue.put(response_entry);
            # self._log(f"CF (Complete) Processed: ID={arbitration_id:X}, Data on Q: {response_entry}") # Debug
            self._reset_isotp_state() # Reset state after completion
        # Check if we need to send another Flow Control (if Block Size was set by sender's FC)
        elif self._isotp_block_size > 0 and self._isotp_frames_since_fc >= self._isotp_block_size:
            self._isotp_frames_since_fc = 0 # Reset counter for this block
            # Send CTS Flow Control with the same BS and STmin values we received from sender
            st_min_ms_int = int(self._isotp_stmin * 1000) # Convert STmin (seconds) back to ms for sending
            self._send_flow_control(flow_status=FC_STATUS_CTS, block_size=self._isotp_block_size, st_min_ms=st_min_ms_int)
            # self._log(f"CF Processed, sent next FC: ID={arbitration_id:X}, Buffered={len(self._isotp_buffer)}") # Debug


    def _handle_fc(self, arbitration_id: int, data_bytes: List[int]):
        """
        Handles an incoming ISO-TP Flow Control frame. Assumes isotp_lock is held.
        This is relevant if *we* are sending a multi-frame message and receive an FC from the ECU.
        Or, if the ECU sends an FC (e.g., WAIT) while we are receiving CFs.
        """
        if len(data_bytes) < 3: # FC needs PCI, BS, STmin
            self._log(f"Warning: Short Flow Control frame received from {arbitration_id:X}. Length {len(data_bytes)}. Ignoring.")
            return

        pci_byte_fc = data_bytes[0]
        flow_status = pci_byte_fc & 0x0F # FS: Flow Status (CTS, WAIT, OVFLW)
        block_size_rcvd = data_bytes[1] # BS: Block Size
        st_min_raw_rcvd = data_bytes[2] # STmin: Separation Time Minimum

        # Decode STmin (Separation Time Minimum) from received raw byte
        if 0 <= st_min_raw_rcvd <= 0x7F: # 0-127 ms
            st_min_ms = st_min_raw_rcvd
        elif 0xF1 <= st_min_raw_rcvd <= 0xF9: # 100-900 microseconds
            st_min_ms = (st_min_raw_rcvd - 0xF0) * 0.1 # Convert 0.1ms units to ms
        else: # Value is reserved or out of typical range
            self._log(f"Warning: Received FC with STmin raw value {st_min_raw_rcvd:02X} (reserved/invalid). Using 127ms default.")
            st_min_ms = 127 # Per spec, treat reserved/invalid values as max standard value (127ms)

        st_min_sec = st_min_ms / 1000.0 # Convert to seconds for internal use

        flow_status_str = {FC_STATUS_CTS: "CTS", FC_STATUS_WT: "WAIT", FC_STATUS_OVFLW: "OVFLW"}.get(flow_status, f"?({flow_status})")
        # self._log(f"Received Flow Control from {arbitration_id:X}: FS={flow_status_str}, BS={block_size_rcvd}, STmin_raw={st_min_raw_rcvd:02X} ({st_min_ms:.1f}ms)") # Verbose

        # If we are currently waiting for CF frames (i.e., we are the receiver of a multi-frame message)
        # and this FC is from the ECU we are talking to.
        if self._isotp_state == ISOTPState.WAIT_CF and arbitration_id == self._isotp_target_id:
             if flow_status == FC_STATUS_CTS:
                 # The sender (ECU) is telling us its parameters for sending CFs.
                 # We should store these if we were the sender, but as receiver, this is unusual.
                 # More likely, if we sent an FF, the ECU sends an FC back.
                 # If we are in WAIT_CF, it means *we* sent an FF and are waiting for CFs from ECU.
                 # So, an FC from ECU here might be a WAIT or OVFLW.
                 # If it's CTS, it's a bit odd unless it's a re-send of their initial FC.
                 self._isotp_block_size = block_size_rcvd # Store sender's BS preference
                 self._isotp_stmin = st_min_sec # Store sender's STmin preference
                 self._isotp_frames_since_fc = 0 # Reset counter as we received a new FC from them
                 # self._log(f"  -> Updated receiver's understanding of sender's params: BS={block_size_rcvd}, STmin={st_min_sec:.3f}s")
             elif flow_status == FC_STATUS_WT: # Sender (ECU) is asking us to wait
                 self._log(f"Received WAIT Flow Control from sender {arbitration_id:X}. Pausing reception (not fully implemented, continuing to listen).")
                 # TODO: Implement actual wait logic if required (e.g., set a timer before expecting more CFs or re-sending FC after timeout)
             elif flow_status == FC_STATUS_OVFLW: # Sender (ECU) reports overflow
                 self._log(f"Error: Sender {arbitration_id:X} reported OVFLW (Overflow). Resetting ISO-TP state.")
                 self._reset_isotp_state() # Critical error, reset transaction
        # If we are the SENDER and waiting for an FC (ISOTPState.WAIT_FC)
        elif self._isotp_state == ISOTPState.WAIT_FC: # This state is more for when *we* are sending
            # This means we sent an FF or a block of CFs, and now ECU is responding with FC.
            self._isotp_block_size = block_size_rcvd
            self._isotp_stmin = st_min_sec
            # Transition out of WAIT_FC based on flow_status, and continue sending CFs if CTS.
            # This part of logic would be in the sending loop, not here in _parse_incoming_message.
            # For now, just log that we received it.
            # self._log(f"  -> FC received while in WAIT_FC state (likely as sender). BS={block_size_rcvd}, STmin={st_min_sec:.3f}s")
            pass
        else:
            # Received FC in an unexpected state (e.g., IDLE) or from an unexpected ID.
            # self._log(f"Warning: Received Flow Control from {arbitration_id:X} in unexpected ISO-TP state ({self._isotp_state.name}). Ignoring.")
            pass


    def register_live_dashboard_processor(self, processor: Optional[ILiveDataProcessor]):
        """Registers or unregisters the live dashboard data processor."""
        if processor is None:
            if self.live_dashboard_processor: # Only log if there was one to unregister
                self._log("Unregistering live dashboard processor.")
            self.live_dashboard_processor = None
        elif hasattr(processor, 'TARGET_IDS') and callable(getattr(processor, 'process_message', None)):
             target_ids_str = ", ".join(f"{tid:X}" for tid in processor.TARGET_IDS) if processor.TARGET_IDS else "All (if supported by processor)"
             self._log(f"Registering live dashboard processor targeting IDs: {target_ids_str}")
             self.live_dashboard_processor = processor
        else:
             self._log("Error: Invalid live dashboard processor passed (missing TARGET_IDS or process_message).")
             self.live_dashboard_processor = None

    def register_expert_raw_processor(self, processor: Optional[ICanRawMessageProcessor]):
        """Registers or unregisters a raw CAN message processor for the expert tab."""
        if processor:
            self._log(f"Registering expert raw CAN processor: {type(processor).__name__}")
        else:
            if self.expert_raw_processor: # Only log if there was one to unregister
                 self._log(f"Unregistering expert raw CAN processor: {type(self.expert_raw_processor).__name__}")
        self.expert_raw_processor = processor

    def send_custom_can_message(self, arbitration_id: int, data: Union[List[int], bytes], is_extended: bool = False, is_remote: bool = False) -> bool:
        """
        Sends a custom CAN message.
        This is a public method intended for use by features like the CAN Expert Tab.
        It directly calls the internal _send_can_message.
        """
        if not self.is_connected or not self.bus:
            self._log("Error: Cannot send custom CAN message, not connected.")
            return False
        
        # The _send_can_message already logs the attempt.
        # self._log(f"Attempting custom send: ID={arbitration_id:X}, Data={bytes(data).hex().upper()}, Ext={is_extended}, RTR={is_remote}")
        # MODIFIED Call to pass is_remote
        return self._send_can_message(arbitration_id, data, is_extended, is_remote)