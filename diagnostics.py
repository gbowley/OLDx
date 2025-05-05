# diagnostics.py

# Provides logic for handling reading and clearing of fault codes.

import time
import traceback
from typing import Optional, Dict, Any, List, Tuple

# Import local modules
try:
    from can_communication import CanCommunication, UDS_REQUEST_ID, ABS_REQUEST_ID, TCU_REQUEST_ID, COMMANDS, DEFAULT_SESSION, EXTENDED_SESSION, STANDBY_SESSION, decode_nrc
    from known_faults import get_fault_description, format_fault_code, FAULTS_CONFIRMED, FAULTS_PENDING, KNOWN_FAULTS
    from vin_logic import lookup_vehicle_info
    from performance_data import PERFORMANCE_DATA_ITEMS
except ImportError as e:
    print(f"Error importing modules in diagnostics.py: {e}")
    # Define dummy fallbacks if imports fail
    def get_fault_description(code): return "Lookup Error"
    def format_fault_code(code): return "Format Error"
    def lookup_vehicle_info(vin): return None
    def decode_nrc(nrc: int) -> str: return f"Decode Error {nrc:02X}"
    class CanCommunication: pass
    FAULTS_CONFIRMED="confirmed"; FAULTS_PENDING="pending"; KNOWN_FAULTS={}
    UDS_REQUEST_ID=0x7E0; ABS_REQUEST_ID=0x6F4; TCU_REQUEST_ID=0x7E1; COMMANDS={}
    DEFAULT_SESSION=0x01; EXTENDED_SESSION=0x03; STANDBY_SESSION=0x89
    PERFORMANCE_DATA_ITEMS = {}

NO_FAULT_RESPONSE = "No response from module"
VIN_READ_ERROR = "Could not read VIN"
ECU_SESSION_START_TIMEOUT = 8.0
ABS_SESSION_START_TIMEOUT = 5.0

# --- VIN Reading ---
def get_vin(can_comm: CanCommunication, status_callback: callable) -> Optional[str]:
    if not can_comm or not can_comm.is_connected: status_callback("VIN Read Error: Not connected."); return None
    vin_string: Optional[str] = None
    req_id = UDS_REQUEST_ID
    session_started_ok = False
    time.sleep(0.1) # Small delay before starting
    status_callback("Attempting to start diagnostic session ($10 03)...")
    session_cmd_data = [0x02, 0x10, EXTENDED_SESSION]
    session_success, session_response = can_comm.send_command(
        'custom_session_start_vin', req_id=req_id, data=session_cmd_data,
        timeout=ECU_SESSION_START_TIMEOUT, expected_response_service_id=0x50
    )

    is_nrc_for_session_start = False; nrc_msg = ""
    if session_response and len(session_response) >= 2:
        try:
             if len(session_response) >= 4 and session_response[1] == 0x7F and session_response[2] == 0x10: # SF NRC
                 is_nrc_for_session_start = True; nrc = session_response[3]; nrc_msg = f" (NRC: {nrc:02X} - {decode_nrc(nrc)})"
             elif len(session_response) >= 5 and session_response[2] == 0x7F and session_response[3] == 0x10: # MF NRC
                 is_nrc_for_session_start = True; nrc = session_response[4]; nrc_msg = f" (NRC: {nrc:02X} - {decode_nrc(nrc)})"
        except IndexError: status_callback(f"Warning: IndexError checking session response NRC: {session_response}"); session_started_ok = True # Allow proceeding if parse fails

    if not is_nrc_for_session_start:
        session_started_ok = True
        if session_success: status_callback("Extended diagnostic session started (Positive confirmation received).")
        else: resp_hex = bytes(session_response).hex().upper() if session_response else 'None'; status_callback(f"Extended diagnostic session likely started (Timeout/No positive confirmation, Resp: {resp_hex}). Proceeding...")
    else: status_callback(f"Failed to start session. Negative Response received{nrc_msg}."); session_started_ok = False

    time.sleep(0.1)

    if session_started_ok:
        status_callback("Requesting VIN (Service $09 PID $02)...")
        success, response = can_comm.send_command('getVin', timeout=5.0, expected_response_service_id=0x49)

        if not success or not response:
            nrc_msg_vin = ""
            if response:
                 try:
                     if len(response) >= 4 and response[1] == 0x7F: nrc=response[3]; req_sid_echo=response[2]; nrc_msg_vin=f" (NRC: {nrc:02X} - {decode_nrc(nrc)}) to service ${req_sid_echo:02X}"
                     elif len(response) >= 5 and response[2] == 0x7F: nrc=response[4]; req_sid_echo=response[3]; nrc_msg_vin=f" (NRC: {nrc:02X} - {decode_nrc(nrc)}) to service ${req_sid_echo:02X}"
                 except IndexError: nrc_msg_vin = f" (NRC Parse Error on Resp: {bytes(response).hex()})"
            status_callback(f"VIN Request Failed: {NO_FAULT_RESPONSE if response is None else 'Negative Response'}{nrc_msg_vin}"); vin_string = VIN_READ_ERROR
        elif len(response) < 4: status_callback(f"VIN Request: Invalid response format (too short) {bytes(response).hex()}"); vin_string = VIN_READ_ERROR
        else:
            sid_index = -1; pid_hi_index = -1; vin_start_index = -1
            first_byte = response[0]; pci_type = (first_byte >> 4) & 0x0F
            if pci_type == 0x0 and len(response) >= 4: sid_index = 1; pid_hi_index = 2
            elif pci_type == 0x1 and len(response) >= 5: sid_index = 2; pid_hi_index = 3
            elif first_byte == 0x00 and len(response) >= 5: sid_index = 2; pid_hi_index = 3

            if sid_index == -1 or response[sid_index] != 0x49 or len(response) <= pid_hi_index + 1 or response[pid_hi_index] != 0x02:
                 status_callback(f"VIN Request: Invalid SID/PID HI format {bytes(response).hex()}"); vin_string = VIN_READ_ERROR
            else:
                 pid_lo_or_seq_byte = response[pid_hi_index + 1]
                 if pid_lo_or_seq_byte == 0x00: vin_start_index = pid_hi_index + 2
                 elif pid_lo_or_seq_byte == 0x01 and len(response) > pid_hi_index + 2: status_callback(f"VIN Response: Detected sequence counter ({pid_lo_or_seq_byte:02X}), adjusting."); vin_start_index = pid_hi_index + 2
                 else: status_callback(f"VIN Request: Invalid PID LO / Sequence format {bytes(response).hex()}"); vin_string = VIN_READ_ERROR

                 if vin_start_index != -1:
                     if len(response) <= vin_start_index: status_callback(f"VIN Response too short after header: {bytes(response).hex()}"); vin_string = VIN_READ_ERROR
                     else:
                         try:
                             vin_bytes = bytes(response[vin_start_index:])
                             vin_string_decoded = ''.join(filter(lambda c: 'A' <= c.upper() <= 'Z' or '0' <= c <= '9', vin_bytes.decode('ascii', errors='ignore'))).upper().strip().replace('I', '').replace('O', '').replace('Q', '')
                             if len(vin_string_decoded) >= 17: vin_string = vin_string_decoded[:17]; status_callback(f"VIN Read OK: {vin_string}")
                             else: status_callback(f"VIN Read Error: Invalid length {len(vin_string_decoded)} -> '{vin_string_decoded}'"); vin_string = VIN_READ_ERROR
                         except Exception as e: status_callback(f"VIN Decode Error: {e}"); vin_string = VIN_READ_ERROR
    else:
        status_callback("VIN Read Skipped - Session start failed."); vin_string = VIN_READ_ERROR
    return vin_string

# --- Fault Parsing ---
def parse_faults(response_data: List[int], protocol_hint: str = "UDS") -> Tuple[List[str], Optional[str]]:
    if not response_data: return [], "Invalid response data (empty)"
    data = list(response_data)
    original_data_for_error = list(response_data)
    service_reply = 0; payload = []; error_msg = None
    try:
        if protocol_hint == "KWP":
            if not data: raise ValueError("KWP response missing SID")
            service_reply = data.pop(0); payload = data
        elif protocol_hint == "OBD":
            if len(data) < 2: raise ValueError("OBD response too short (needs Length, SID)")
            obd_len = data.pop(0)
            if not data: raise ValueError("OBD response missing SID after length byte")
            service_reply = data.pop(0)
            expected_payload_len = max(0, obd_len - 1)
            if len(data) < expected_payload_len: print(f"Warning: OBD length mismatch. Declared payload len={expected_payload_len}, got {len(data)}. Trying anyway.")
            payload = data[:expected_payload_len]
        else: # Assume UDS/ISO-TP
            first_byte = data.pop(0); pci_type = (first_byte >> 4) & 0x0F; sid_index = -1
            if pci_type == 0x0: sid_index = 0
            elif pci_type == 0x1: sid_index = 1 if len(data) >= 1 else -1
            elif first_byte == 0x00 and len(data) >= 2: sid_index = 1
            else: error_msg = f"Unknown UDS PCI/format byte: {first_byte:02X}"; return [], error_msg
            if sid_index == -1 or len(data) <= sid_index: raise ValueError(f"UDS response too short for SID (Index: {sid_index}, Len: {len(data)}, PCI: {first_byte:02X})")
            service_reply = data[sid_index]; payload = data[sid_index+1:]

        if service_reply == 0x7F:
            req_sid_echo = payload[0] if payload else 0x00; nrc = payload[1] if len(payload) > 1 else 0x00
            if nrc == 0 and len(payload) > 2: nrc = payload[2]
            return [], f"Negative Response (NRC: {nrc:02X} - {decode_nrc(nrc)}) to service ${req_sid_echo:02X}"

        faults = []
        if service_reply == 0x53: # KWP $13
            if len(payload) % 2 != 0: raise ValueError("Expected even bytes for KWP $53 reply")
            if not payload: return [], None; [faults.append((payload[i] << 8) + payload[i+1]) for i in range(0, len(payload), 2)]
        elif service_reply == 0x58: # KWP $18
             if not payload: raise ValueError("Missing count byte for KWP $58 reply")
             count = payload.pop(0); expected_len = count * 3
             if count == 0: return [], None
             if len(payload) != expected_len: raise ValueError(f"KWP $58 count mismatch: expected {expected_len}, got {len(payload)}")
             for i in range(count): faults.append((payload[i*3] << 8) + payload[i*3+1])
        elif service_reply == 0x59: # UDS $19
             if not payload: raise ValueError("Missing subfunction reply for UDS $19")
             subfunction_reply = payload.pop(0)
             if subfunction_reply in [0x01, 0x02, 0x0A]:
                 if not payload: return [], None; _ = payload.pop(0); # Skip Mask
                 if not payload: return [], None
                 if len(payload) % 4 == 0: [faults.append((payload[i] << 16) + (payload[i+1] << 8) + payload[i+2]) for i in range(0, len(payload), 4)]
                 elif len(payload) % 3 == 0: print(f"Warning: UDS $19.{subfunction_reply:02X}: Assuming 3-byte DTC format."); [faults.append((payload[i] << 16) + (payload[i+1] << 8) + payload[i+2]) for i in range(0, len(payload), 3)]
                 else: error_msg = f"Unexpected UDS $19.{subfunction_reply:02X} payload length: {len(payload)}"
             else: error_msg = f"Parsing for UDS $19 Subfunction={subfunction_reply:02X} not implemented"
        elif service_reply == 0x43: # OBD $03
             if not payload: return [], None
             if len(payload) > 0 and payload[0] * 2 == len(payload) - 1: print(f"Parsing OBD Mode $03 with leading count byte ({payload[0]})."); payload = payload[1:]
             if len(payload) % 2 != 0: raise ValueError(f"Expected even bytes for OBD $43 DTC payload, got {len(payload)}")
             print(f"Parsing OBD Mode $03 (Payload: {bytes(payload).hex()})"); [faults.append((payload[i] << 8) + payload[i+1]) for i in range(0, len(payload), 2)]
        elif service_reply == 0x47: # OBD $07
             if not payload: return [], None
             if len(payload) > 0 and payload[0] * 2 == len(payload) - 1: print(f"Parsing OBD Mode $07 with leading count byte ({payload[0]})."); payload = payload[1:]
             if len(payload) % 2 != 0: raise ValueError(f"Expected even bytes for OBD $47 DTC payload, got {len(payload)}")
             print(f"Parsing OBD Mode $07 (Payload: {bytes(payload).hex()})"); [faults.append((payload[i] << 8) + payload[i+1]) for i in range(0, len(payload), 2)]
        else: error_msg = f"Parsing for Service Reply ${service_reply:02X} (Hint: {protocol_hint}) not implemented."

    except ValueError as e: error_msg = f"Parsing ValueError: {e} - Response Data: {bytes(original_data_for_error).hex()}"
    except IndexError as e: error_msg = f"Parsing IndexError: {e} - Response Data: {bytes(original_data_for_error).hex()}"
    except Exception as e: error_msg = f"Unexpected parsing error: {type(e).__name__}: {e} - Response Data: {bytes(original_data_for_error).hex()}"

    faults_strings = []
    for f_int in faults:
        if f_int == 0x0000: continue
        if f_int > 0xFFFF: # UDS 3-byte
            fault_letter_map = {0: 'P', 1: 'P', 2: 'P', 3: 'P', 4: 'C', 5: 'C', 6: 'C', 7: 'C', 8: 'B', 9: 'B', 0xA: 'B', 0xB: 'B', 0xC: 'U', 0xD: 'U', 0xE: 'U', 0xF: 'U'}
            first_nybble = (f_int >> 20) & 0xF; fault_letter = fault_letter_map.get(first_nybble, '?'); fault_num_hex = f"{f_int & 0x3FFFFF:05X}"; faults_strings.append(f"{fault_letter}{fault_num_hex}")
        else: # KWP/OBD 2-byte
            faults_strings.append(format_fault_code(f_int))
    if faults_strings and error_msg and "not implemented" not in error_msg: faults_strings.append(f"(Parse Warning: {error_msg})"); error_msg = None
    return faults_strings, error_msg

# --- Module Parameter Determination ---
def _determine_module_params(module_name: str, vehicle_info: Optional[Dict[str, Any]]) -> Optional[Tuple[int, bool, int]]:
    default_session_type = EXTENDED_SESSION
    if not vehicle_info:
        print(f"Warning: No vehicle info for {module_name}, using simple defaults.")
        if module_name == "ECM": return UDS_REQUEST_ID, True, EXTENDED_SESSION
        if module_name == "TCU": return TCU_REQUEST_ID, False, DEFAULT_SESSION
        if module_name == "ABS": return ABS_REQUEST_ID, True, STANDBY_SESSION
        print(f"Warning: Unknown default module '{module_name}'"); return None
    is_present = False
    if module_name == "ECM": is_present = bool(vehicle_info.get("ECU_Program"))
    elif module_name == "TCU": is_present = bool(vehicle_info.get("TCU_Program"))
    elif module_name == "ABS": is_present = bool(vehicle_info.get("ABS_Module")) or bool(vehicle_info.get("ABS_Program"))
    if not is_present: print(f"Info: Module '{module_name}' not specified in vehicle data. Skipping."); return None
    can_id = None; needs_session = False; session_type = default_session_type
    if module_name == "ECM": can_id = UDS_REQUEST_ID; needs_session = True; session_type = EXTENDED_SESSION
    elif module_name == "TCU": can_id = TCU_REQUEST_ID; needs_session = False; session_type = DEFAULT_SESSION
    elif module_name == "ABS":
        abs_module_type = vehicle_info.get("ABS_Module", ""); abs_program = vehicle_info.get("ABS_Program", "")
        can_id = ABS_REQUEST_ID
        if "Bosch BL ESP" in abs_module_type: needs_session = True; session_type = EXTENDED_SESSION; print(f"ABS ({abs_module_type}): Determined UDS Extended Session needed.")
        elif "Bosch Non-BL ABS/TC" in abs_module_type or "BB68604" in abs_program: needs_session = True; session_type = STANDBY_SESSION; print(f"ABS ({abs_module_type or abs_program}): Determined KWP Standby Session ($89) needed.")
        else: needs_session = True; session_type = STANDBY_SESSION; print(f"ABS (Type: '{abs_module_type}', Prog: '{abs_program}'): Assuming KWP Standby Session ($89) needed (default guess).")
    if can_id is None: print(f"Warning: Could not determine CAN ID for '{module_name}'"); return None
    return can_id, needs_session, session_type

# --- Fault Reading ---
def get_faults(can_comm: CanCommunication, status_callback: callable, vehicle_info: Optional[Dict[str, Any]]):
    if not can_comm or not can_comm.is_connected: status_callback("Error: CAN not connected."); return None
    all_faults = {}
    def read_module_faults_internal(module_name: str, fault_type_cmd_map: Dict[str, List[str]]):
        nonlocal all_faults
        status_callback(f"--- Reading {module_name} Faults ---")
        params = _determine_module_params(module_name, vehicle_info)
        if params is None: status_callback(f"{module_name}: Skipped."); all_faults[module_name] = ["Skipped (N/A or Unknown Config)"]; return

        req_id, needs_session, session_type = params
        session_started_by_us = False; session_check_ok = True
        current_session_timeout = ECU_SESSION_START_TIMEOUT if req_id in [UDS_REQUEST_ID, TCU_REQUEST_ID] else ABS_SESSION_START_TIMEOUT

        if module_name not in all_faults: all_faults[module_name] = []
        time.sleep(0.1)

        if needs_session:
            status_callback(f"{module_name}: Starting diag session (${session_type:02X})...");
            session_cmd_data = [0x02, 0x10, session_type]
            session_success, session_response = can_comm.send_command(
                f'custom_session_start_{module_name}', req_id=req_id, data=session_cmd_data,
                timeout=current_session_timeout, expected_response_service_id=0x50
            )
            is_nrc_for_session_start = False; nrc_msg = ""
            if session_response and len(session_response) >= 2:
                try:
                    is_kwp_module = req_id == ABS_REQUEST_ID
                    if is_kwp_module and session_response[0] == 0x7F and session_response[1] == 0x10: is_nrc_for_session_start = True; nrc = session_response[2] if len(session_response) > 2 else 0; nrc_msg = f" (NRC: {nrc:02X} - {decode_nrc(nrc)})"
                    elif not is_kwp_module:
                        if len(session_response) >= 4 and session_response[1] == 0x7F and session_response[2] == 0x10: is_nrc_for_session_start = True; nrc = session_response[3]; nrc_msg = f" (NRC: {nrc:02X} - {decode_nrc(nrc)})"
                        elif len(session_response) >= 5 and session_response[2] == 0x7F and session_response[3] == 0x10: is_nrc_for_session_start = True; nrc = session_response[4]; nrc_msg = f" (NRC: {nrc:02X} - {decode_nrc(nrc)})"
                except IndexError: status_callback(f"Warning: IndexError checking session NRC: {session_response}")
            if not is_nrc_for_session_start:
                session_check_ok = True; session_started_by_us = True
                if session_success: status_callback(f"{module_name}: Session started (Positive confirmation received).")
                else: resp_hex = bytes(session_response).hex().upper() if session_response else 'None'; status_callback(f"{module_name}: Session likely started (Timeout/No positive confirmation, Resp: {resp_hex}). Proceeding...")
            else: status_callback(f"{module_name}: Failed start session ${session_type:02X}. Negative Response{nrc_msg}"); session_check_ok = False
        else: status_callback(f"{module_name}: Session start not required."); session_check_ok = True

        if session_check_ok:
            for fault_type_str, cmd_list in fault_type_cmd_map.items():
                 status_callback(f"Requesting {fault_type_str} faults from {module_name} (ID: {req_id:X})...")
                 faults_found_for_type = set(); error_msg_for_type = None; read_attempted_for_type = False

                 for cmd_index, cmd_name in enumerate(cmd_list):
                    if faults_found_for_type and error_msg_for_type is None: break

                    status_callback(f"Attempting cmd: {cmd_name}...")
                    cmd_req_id_override = None; cmd_data = None; is_raw_s_command = cmd_name.startswith('s') and len(cmd_name) >= 7

                    if is_raw_s_command:
                        try: raw_id_hex = cmd_name[1:5]; raw_data_hex = cmd_name[5:]; cmd_req_id_override = int(raw_id_hex, 16); cmd_data = bytes.fromhex(raw_data_hex)
                        except Exception as e: status_callback(f"{module_name}: Failed parse raw cmd '{cmd_name}': {e}"); error_msg_for_type = f"Bad Raw Cmd {cmd_name}"; continue
                    else:
                         command_tuple = COMMANDS.get(cmd_name);
                         if not command_tuple: status_callback(f"{module_name}: Cmd '{cmd_name}' undef."); error_msg_for_type = f"Cmd {cmd_name} Undef"; continue
                         cmd_req_id_from_dict, base_data = command_tuple; cmd_data = base_data; cmd_req_id_override = cmd_req_id_from_dict

                    current_req_id = cmd_req_id_override if cmd_req_id_override is not None else req_id
                    if current_req_id is None or cmd_data is None: status_callback(f"{module_name}: Config error cmd '{cmd_name}'"); error_msg_for_type = f"Bad Cmd Cfg {cmd_name}"; continue

                    expected_reply_sid = None; service_being_sent = 0; protocol_hint = "UDS"
                    if current_req_id == ABS_REQUEST_ID: protocol_hint = "KWP"; service_being_sent = cmd_data[1] if len(cmd_data) > 1 else 0; expected_reply_sid = {0x13: 0x53, 0x18: 0x58, 0x14: 0x54}.get(service_being_sent)
                    elif cmd_name in ['getObdConfirmedFaults', 'getObdPendingFaults']: protocol_hint = "OBD"; service_being_sent = cmd_data[1]; expected_reply_sid = {0x03: 0x43, 0x07: 0x47}.get(service_being_sent)
                    else: protocol_hint = "UDS"; service_being_sent = cmd_data[1] if len(cmd_data) > 1 else 0; expected_reply_sid = (service_being_sent + 0x40) if service_being_sent not in [0x10, 0x00] else None

                    status_callback(f"(Using {protocol_hint} cmd: ID={current_req_id:X}, Data={bytes(cmd_data).hex()})")
                    read_attempted_for_type = True
                    current_timeout = 3.0
                    success, response = can_comm.send_command(
                        f'custom_{cmd_name}', req_id=current_req_id, data=cmd_data,
                        expected_response_service_id=expected_reply_sid, timeout=current_timeout
                    )

                    if success and response:
                        parsed_faults, parse_error = parse_faults(response, protocol_hint=protocol_hint)
                        if parse_error:
                            status_callback(f"{module_name} ({fault_type_str}, cmd {cmd_name}): Parse Error - {parse_error}")
                            error_msg_for_type = f"Parse Error ({parse_error})"
                            if cmd_index < len(cmd_list) - 1: status_callback(f"--- Trying fallback command due to parse error: {cmd_list[cmd_index+1]} ---"); continue
                            else: break
                        elif parsed_faults:
                            faults_found_for_type.update(parsed_faults); error_msg_for_type = None
                            status_callback(f"{module_name} ({fault_type_str}, cmd {cmd_name}): Found {len(parsed_faults)} fault(s).")
                            break
                        else:
                            error_msg_for_type = None; status_callback(f"{module_name} ({fault_type_str}, cmd {cmd_name}): No faults reported by this command.")
                            break

                    elif not success and response is None:
                        current_cmd_error = NO_FAULT_RESPONSE; status_callback(f"{module_name} ({fault_type_str}, cmd {cmd_name}): {current_cmd_error}"); error_msg_for_type = current_cmd_error
                        if cmd_index < len(cmd_list) - 1: status_callback(f"--- Trying fallback command: {cmd_list[cmd_index+1]} ---"); continue
                        else: break

                    elif not success and response:
                        nrc = 0; req_sid_echo = 0; nrc_text = "Negative Response";
                        try:
                             if protocol_hint == "KWP" and len(response) >= 3 and response[0] == 0x7F: req_sid_echo=response[1]; nrc=response[2]
                             elif protocol_hint != "KWP":
                                 if len(response) >= 4 and response[1] == 0x7F: req_sid_echo=response[2]; nrc=response[3]
                                 elif len(response) >= 5 and response[2] == 0x7F: req_sid_echo=response[3]; nrc=response[4]
                             if nrc != 0: nrc_text = f"NRC: {nrc:02X} ({decode_nrc(nrc)}) for SID ${req_sid_echo:02X}"
                             else: nrc_text = f"NRC (Unknown Format: {bytes(response).hex()})"
                        except Exception as e: nrc_text = f"NRC (Parse Error: {e})"
                        error_msg_for_type = nrc_text
                        if nrc in [0x11, 0x12] and cmd_index < len(cmd_list) - 1: status_callback(f"{module_name} ({fault_type_str}, cmd {cmd_name}): {nrc_text}. Trying alternative command..."); continue
                        else: status_callback(f"{module_name} ({fault_type_str}, cmd {cmd_name}): Failed - {nrc_text}"); break
                    time.sleep(0.05)

                 if not read_attempted_for_type: all_faults[module_name].append(f"{module_name} - {fault_type_str.capitalize()} read skipped (cmd/config error).")
                 elif faults_found_for_type:
                     for fault in sorted(list(faults_found_for_type)):
                         if fault: all_faults[module_name].append(f"{fault} - {get_fault_description(fault)} [{fault_type_str.upper()}]")
                         else: all_faults[module_name].append(f"Invalid fault code parsed [{fault_type_str.upper()}]")
                 elif not error_msg_for_type: all_faults[module_name].append(f"{module_name} - No {fault_type_str} faults found.")
                 else: all_faults[module_name].append(f"{module_name} - Read {fault_type_str.capitalize()} faults: {error_msg_for_type}")
        else: all_faults[module_name].append(f"{module_name}: Could not start required session. Read skipped.")

        if session_started_by_us:
            if module_name == "ABS" and session_type == STANDBY_SESSION: status_callback(f"{module_name}: Skipping return to default session.")
            else:
                status_callback(f"{module_name}: Returning to default session..."); default_session_data = [0x02, 0x10, DEFAULT_SESSION]
                can_comm.send_command(f'custom_session_end_{module_name}', req_id=req_id, data=default_session_data, timeout=1.5)
                time.sleep(0.05)

    ecm_reads = { FAULTS_CONFIRMED: ['getEngineFaultsNormal', 'getObdConfirmedFaults'], FAULTS_PENDING: ['getEngineFaultsNormalPending', 'getObdPendingFaults'] }
    tcu_reads = { FAULTS_CONFIRMED: ['getGearboxFaultsNormal'] }
    abs_reads = { FAULTS_CONFIRMED: ['s06F4031300FF', 's06F4041800FF00'] }

    read_module_faults_internal("ECM", ecm_reads)
    read_module_faults_internal("TCU", tcu_reads)
    read_module_faults_internal("ABS", abs_reads)

    status_callback("Fault reading finished.")
    return all_faults

# --- Fault Clearing ---
def clear_faults(can_comm: CanCommunication, status_callback: callable, vehicle_info: Optional[Dict[str, Any]]):
    if not can_comm or not can_comm.is_connected: status_callback("Error: CAN not connected."); return False
    results = {}
    def clear_module_faults_internal(module_name: str, commands: List[str]):
        nonlocal results
        status_callback(f"--- Attempting to clear faults from {module_name} ---")
        params = _determine_module_params(module_name, vehicle_info)
        if params is None: status_callback(f"{module_name}: Skipped."); results[module_name] = ["Skipped (N/A or Unknown Config)"]; return False

        req_id, needs_session, session_type = params
        if module_name == "TCU": needs_session = True; session_type = EXTENDED_SESSION; status_callback(f"TCU: Forcing Extended Session check for clear operation.")

        did_start_session = False; session_check_ok = True; module_results = []; all_clear_success_for_module = True
        current_session_timeout = ECU_SESSION_START_TIMEOUT if req_id in [UDS_REQUEST_ID, TCU_REQUEST_ID] else ABS_SESSION_START_TIMEOUT
        time.sleep(0.1)

        if needs_session:
            status_callback(f"{module_name}: Starting session (${session_type:02X}) for clear...");
            session_cmd_data = [0x02, 0x10, session_type]
            success, session_response = can_comm.send_command(f'custom_clear_sess_start_{module_name}', req_id=req_id, data=session_cmd_data, timeout=current_session_timeout, expected_response_service_id=0x50)
            is_nrc_for_session_start = False; nrc_msg = ""
            if session_response and len(session_response) >= 2:
                 try:
                    is_kwp_module = req_id == ABS_REQUEST_ID
                    if is_kwp_module and session_response[0] == 0x7F and session_response[1] == 0x10: is_nrc_for_session_start = True; nrc = session_response[2] if len(session_response) > 2 else 0; nrc_msg = f" (NRC: {nrc:02X} - {decode_nrc(nrc)})"
                    elif not is_kwp_module:
                        if len(session_response) >= 4 and session_response[1] == 0x7F and session_response[2] == 0x10: is_nrc_for_session_start = True; nrc = session_response[3]; nrc_msg = f" (NRC: {nrc:02X} - {decode_nrc(nrc)})"
                        elif len(session_response) >= 5 and session_response[2] == 0x7F and session_response[3] == 0x10: is_nrc_for_session_start = True; nrc = session_response[4]; nrc_msg = f" (NRC: {nrc:02X} - {decode_nrc(nrc)})"
                 except IndexError: status_callback(f"Warning: IndexError checking clear session NRC: {session_response}")
            if not is_nrc_for_session_start: session_check_ok = True; did_start_session = True; status_callback(f"{module_name}: Session started for clear.")
            else: status_callback(f"{module_name}: Failed start session for clear. Clear may fail. Negative Response{nrc_msg}"); session_check_ok = False; all_clear_success_for_module = False
        else: status_callback(f"{module_name}: Session start not required for clear."); session_check_ok = True

        if session_check_ok:
            for cmd_name in commands:
                cmd_req_id_override = None; cmd_data = None; is_raw_s_command = cmd_name.startswith('s') and len(cmd_name) >= 7
                expected_reply_sid = None; service_being_sent = 0; protocol_hint = "UDS"
                if is_raw_s_command:
                     try: raw_id_hex = cmd_name[1:5]; raw_data_hex = cmd_name[5:]; cmd_req_id_override = int(raw_id_hex, 16); cmd_data = bytes.fromhex(raw_data_hex); service_being_sent = cmd_data[1] if len(cmd_data)>1 else 0; protocol_hint = "KWP" if cmd_req_id_override == ABS_REQUEST_ID else "UDS"; expected_reply_sid = 0x54 if service_being_sent == 0x14 else None; status_callback(f"(Using raw {protocol_hint} clear cmd: ID={cmd_req_id_override:X}, Data={cmd_data.hex()})")
                     except Exception as e: status_callback(f"{module_name}: Failed parse raw clear cmd '{cmd_name}': {e}"); module_results.append(f"Bad Raw Cmd {cmd_name}"); all_clear_success_for_module = False; continue
                else: # Standard command
                     command_tuple = COMMANDS.get(cmd_name);
                     if not command_tuple: status_callback(f"{module_name}: Clear Cmd '{cmd_name}' undef."); module_results.append(f"Cmd {cmd_name}: Undef"); all_clear_success_for_module = False; continue
                     cmd_req_id_from_dict, base_data = command_tuple; cmd_data = base_data; cmd_req_id_override = cmd_req_id_from_dict
                     protocol_hint = "UDS"; service_being_sent = cmd_data[1] if len(cmd_data)>1 else 0; expected_reply_sid = 0x54 if service_being_sent == 0x14 else None
                     if service_being_sent == 0x04: protocol_hint = "OBD"; expected_reply_sid = 0x44
                     status_callback(f"(Using {protocol_hint} clear cmd: ID={cmd_req_id_override:X}, Data={bytes(cmd_data).hex()})")

                current_req_id = cmd_req_id_override if cmd_req_id_override is not None else req_id
                success, response = can_comm.send_command(f'custom_{cmd_name}', req_id=current_req_id, data=cmd_data, expected_response_service_id=expected_reply_sid, timeout=5.0)
                result_str = f"Cmd {cmd_name}: "; nrc_msg_clear = ""
                if success: result_str += "Success"
                else:
                    all_clear_success_for_module = False;
                    if response:
                         try:
                             nrc = 0; req_sid_echo = 0
                             if protocol_hint == "KWP" and len(response) >= 3 and response[0] == 0x7F: req_sid_echo=response[1]; nrc=response[2]
                             elif protocol_hint != "KWP":
                                 if len(response) >= 4 and response[1] == 0x7F: req_sid_echo=response[2]; nrc=response[3]
                                 elif len(response) >= 5 and response[2] == 0x7F: req_sid_echo=response[3]; nrc=response[4]
                             if nrc != 0: nrc_msg_clear=f" (NRC: {nrc:02X} - {decode_nrc(nrc)}) for SID ${req_sid_echo:02X}"
                             else: nrc_msg_clear = f" (NRC Unknown Format: {bytes(response).hex()})"
                         except Exception as e: nrc_msg_clear = f" (NRC Parse Error: {e})"
                    result_str += f"Failed{nrc_msg_clear}" if nrc_msg_clear else f"Failed ({NO_FAULT_RESPONSE if response is None else 'Timeout/Other'})"
                module_results.append(result_str); time.sleep(0.1)
        else: module_results.append(f"{module_name}: Session start failed, clear skipped."); all_clear_success_for_module = False

        if did_start_session:
            if module_name == "ABS" and session_type == STANDBY_SESSION: status_callback(f"{module_name}: Skipping return to default session.")
            else:
                status_callback(f"{module_name}: Returning to default session..."); default_session_data = [0x02, 0x10, DEFAULT_SESSION]
                can_comm.send_command(f'custom_clear_sess_end_{module_name}', req_id=req_id, data=default_session_data, timeout=1.0)

        results[module_name] = module_results; status_callback(f"Finished clearing {module_name}.")
        return all_clear_success_for_module

    ecm_clears = ['clearEngineFaultsNormal']
    tcu_clears = ['clearGearboxFaultsNormal']
    abs_clears = ['s06F40314FF00']

    clear_module_faults_internal("ECM", ecm_clears)
    clear_module_faults_internal("TCU", tcu_clears)
    clear_module_faults_internal("ABS", abs_clears)

    status_callback("Fault clearing process finished.")
    return results

# --- Performance Data Transformation ---
def _transform_data(raw_data, offset, multiplier, round_dp, is_time):
    if raw_data is None: return "Error"
    try:
        # Handle specific "Never" case
        if isinstance(raw_data, int) and raw_data == 0xFF000000 and multiplier == 0.1 and is_time:
            return "Never"

        value = float(raw_data) + offset
        value *= multiplier

        if is_time:
            h, m, s = 0, 0, 0 # Initialize h, m, s
            if value < 0:
                return "Invalid Time" # Return before calculating h, m, s

            value = max(0, value) # Ensure non-negative
            h = int(value // 3600)
            m = int((value % 3600) // 60)
            s = round(value % 60)

            if s >= 60: s = 59; m += 1;
            if m >= 60: m = 59; h += 1;
            return f"{h:02}:{m:02}:{s:02} (H:M:S)"
        else:
             if round_dp is not None and isinstance(round_dp, int) and round_dp >= 0:
                 return f"{value:.{round_dp}f}"
             else:
                 return str(int(value)) if value == int(value) else str(value)
    except Exception as e:
        print(f"Error transforming raw data '{raw_data}' (offset={offset}, mult={multiplier}, dp={round_dp}, is_time={is_time}): {type(e).__name__} - {e}")
        return "Transform Error"


# --- Get Performance Data ---
def get_performance_data(can_comm: CanCommunication, status_callback: callable):
    if not can_comm or not can_comm.is_connected: status_callback("Error: CAN not connected."); return None
    results = {}; raw_values = {}; status_callback("Reading performance data...")
    session_started_by_us = False; req_id = UDS_REQUEST_ID; time.sleep(0.1)
    status_callback("Attempting to start extended session for Perf Data...")
    session_cmd_data = [0x02, 0x10, EXTENDED_SESSION]
    session_success, session_response = can_comm.send_command( 'custom_session_start_perf', req_id=req_id, data=session_cmd_data, timeout=ECU_SESSION_START_TIMEOUT, expected_response_service_id=0x50)

    session_check_ok = False; nrc_msg = ""; is_nrc_for_session_start = False
    if session_response and len(session_response) >= 2:
         try:
             if len(session_response) >= 4 and session_response[1] == 0x7F and session_response[2] == 0x10: is_nrc_for_session_start = True; nrc = session_response[3]; nrc_msg = f" (NRC: {nrc:02X} - {decode_nrc(nrc)})"
             elif len(session_response) >= 5 and session_response[2] == 0x7F and session_response[3] == 0x10: is_nrc_for_session_start = True; nrc = session_response[4]; nrc_msg = f" (NRC: {nrc:02X} - {decode_nrc(nrc)})"
         except IndexError: status_callback("Warning: IndexError checking perf session NRC")
    if not is_nrc_for_session_start:
        session_check_ok = True; session_started_by_us = True
        if session_success: status_callback("Extended session started for Perf Data.")
        else: status_callback("Extended session likely active (No positive confirm). Proceeding...")
    else: status_callback(f"Warning: Failed start Extended Session{nrc_msg}. Perf data read might fail.");

    read_errors = 0
    if session_check_ok:
        for name, (did, _, _, _, _) in PERFORMANCE_DATA_ITEMS.items():
            if name.startswith("---") or name.startswith("%Time") or "Estimated Dist" in name: continue
            status_callback(f"Reading {name} (DID {did})..."); command = f"p{did}"; did_hi = int(did[0:2], 16); did_lo = int(did[2:4], 16)
            success, response = can_comm.send_command(command, timeout=3.0, expected_response_service_id=0x62)
            raw_value = None
            if success and response and len(response) >= 3:
                data_start_index = -1; first_byte = response[0]; pci_type = (first_byte >> 4) & 0x0F; sid_index = -1
                if pci_type == 0x0: sid_index = 1
                elif pci_type == 0x1: sid_index = 2
                elif first_byte == 0x00: sid_index = 2
                if sid_index != -1 and len(response) > sid_index + 2 and response[sid_index] == 0x62 and response[sid_index+1] == did_hi and response[sid_index+2] == did_lo: data_start_index = sid_index + 3
                elif response[0] == 0x62 and len(response) > 2 and response[1] == did_hi and response[2] == did_lo: data_start_index = 3
                if data_start_index != -1:
                     data_bytes_available = len(response) - data_start_index; raw_value=0
                     if data_bytes_available >= 4: raw_value = (response[data_start_index] << 24) + (response[data_start_index+1] << 16) + (response[data_start_index+2] << 8) + response[data_start_index+3]
                     elif data_bytes_available == 3: raw_value = (response[data_start_index] << 16) + (response[data_start_index+1] << 8) + response[data_start_index+2]
                     elif data_bytes_available == 2: raw_value = (response[data_start_index] << 8) + response[data_start_index+1]
                     elif data_bytes_available == 1: raw_value = response[data_start_index]
                     raw_values[name] = raw_value
                else: results[name] = f"DID/Format mismatch Resp: {bytes(response).hex()}"; status_callback(f"{name}: DID/Format Mismatch"); read_errors += 1
            elif not success:
                nrc_str_perf = ""
                if response:
                    try:
                        nrc=0; req_sid_echo=0
                        if len(response) >= 4 and response[1] == 0x7F: req_sid_echo=response[2]; nrc=response[3]
                        elif len(response) >= 5 and response[2] == 0x7F: req_sid_echo=response[3]; nrc=response[4]
                        if nrc != 0: nrc_str_perf = f" (NRC: {nrc:02X} - {decode_nrc(nrc)}) to SID ${req_sid_echo:02X}"
                        else: nrc_str_perf = f" (Neg Resp Unknown Fmt: {bytes(response).hex()})"
                    except Exception: nrc_str_perf = " (NRC Parse Error)"
                results[name] = NO_FAULT_RESPONSE if response is None else f"Read Failed{nrc_str_perf}"; status_callback(f"{name}: {results[name]}"); read_errors += 1
            else: results[name] = f"Invalid Resp Struct (Success=True, Resp=None)"; status_callback(f"{name}: Invalid Resp Struct"); read_errors += 1

            if raw_value is None and results.get(name) is None: results[name] = "Read Error (No Data)"
            time.sleep(0.05)
    else: status_callback("Performance data read skipped - Session start failed."); return None

    if session_started_by_us: status_callback("Attempting return to default session after Perf Data..."); default_session_data = [0x02, 0x10, DEFAULT_SESSION]; can_comm.send_command('custom_session_end_perf', req_id=req_id, data=default_session_data, timeout=1.5)

    # --- Process Results & Calculations ---
    # First, transform all successfully read raw values
    for name, (did, offset, mult, r_dp, is_t) in PERFORMANCE_DATA_ITEMS.items():
         if name not in results: # Only process if no error recorded during read
             raw_val = raw_values.get(name)
             results[name] = _transform_data(raw_val, offset, mult, r_dp, is_t) if raw_val is not None else "Read Error (Missing Raw)"

    # Use the intermediate 'results' dict (containing transformed values or errors) for calculations
    # Use valid_raw_values only for the calculation inputs where raw numbers are needed
    valid_raw_values = {k: v for k, v in raw_values.items() if v is not None and isinstance(v, (int, float))}

    # Calculate % Time @ TPS
    tps_times = {k: valid_raw_values[k] * 0.1 for k in valid_raw_values if k.startswith("Time@TPS")}
    total_tps_time = sum(tps_times.values())
    if total_tps_time > 0.001:
        results["--- TPS Time (%) ---"] = "" # Add header to results
        for k, v in tps_times.items():
            if k in PERFORMANCE_DATA_ITEMS: # Check if key exists in original definition
                 results[f"%{k}"] = f"{(v/total_tps_time)*100:.1f}%" # Add % key to results

    # Calculate % Time @ RPM
    rpm_times = {k: valid_raw_values[k] * 0.1 for k in valid_raw_values if k.startswith("Time@RPM")}
    total_rpm_time = sum(rpm_times.values())
    if total_rpm_time > 0.001:
        results["--- RPM Time (%) ---"] = ""
        for k, v in rpm_times.items():
            if k in PERFORMANCE_DATA_ITEMS:
                 results[f"%{k}"] = f"{(v/total_rpm_time)*100:.1f}%"

    # Calculate % Time @ Speed & Estimated Distance
    speed_times = {k: valid_raw_values[k] * 0.1 for k in valid_raw_values if k.startswith("Time@Speed")}
    total_speed_time = sum(speed_times.values()); total_estimated_km = 0;
    speed_bands_mid = {"Time@Speed 0-30": 15, "Time@Speed 30-60": 45, "Time@Speed 60-90": 75, "Time@Speed 90-120": 105, "Time@Speed 120-150": 135, "Time@Speed 150-180": 165, "Time@Speed 180-210": 195, "Time@Speed 210+": 225}
    if total_speed_time > 0.001:
        results["--- Speed Time (%) ---"] = ""
        for name, time_val in speed_times.items():
            if name in PERFORMANCE_DATA_ITEMS:
                 results[f"%{name}"] = f"{(time_val/total_speed_time)*100:.1f}%";
                 mid_speed = speed_bands_mid.get(name, 0);
                 if mid_speed > 0:
                      total_estimated_km += (time_val / 3600.0) * mid_speed

    results["--- Estimated Distance ---"] = "";
    results["Total Estimated Dist (km)"] = f"{total_estimated_km:.0f}";
    results["Total Estimated Dist (miles)"] = f"{total_estimated_km / 1.609:.0f}"

    if read_errors > 0: status_callback(f"Finished reading performance data with {read_errors} read errors.")
    else: status_callback("Finished reading performance data.")

    # --- Corrected Final Dictionary Assembly ---
    # Create the final dictionary ensuring original order and including calculated values
    final_ordered_results = {}
    # Add original items first (transformed values or errors)
    for name in PERFORMANCE_DATA_ITEMS.keys():
         # Exclude headers defined within PERFORMANCE_DATA_ITEMS if any (though unlikely)
         if not name.startswith("---"):
            final_ordered_results[name] = results.get(name, "Data Missing") # Use value from results dict

    # Add calculated sections and their corresponding percentage values
    for section_key in ["--- TPS Time (%) ---","--- RPM Time (%) ---","--- Speed Time (%) ---","--- Estimated Distance ---"]:
        if section_key in results:
            final_ordered_results[section_key] = results[section_key] # Add the header
            # Add all keys starting with '%' that belong to this section header's prefix
            prefix_to_match = section_key[4:section_key.find(' Time')] # Extracts "TPS", "RPM", "Speed"
            for key, value in results.items():
                 if key.startswith(f"%Time@{prefix_to_match}"):
                      final_ordered_results[key] = value

    # Add distance values explicitly if calculated
    if "Total Estimated Dist (km)" in results: final_ordered_results["Total Estimated Dist (km)"] = results["Total Estimated Dist (km)"]
    if "Total Estimated Dist (miles)" in results: final_ordered_results["Total Estimated Dist (miles)"] = results["Total Estimated Dist (miles)"]

    return final_ordered_results