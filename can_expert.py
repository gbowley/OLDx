# can_expert.py
from __future__ import annotations # MUST BE THE VERY FIRST LINE OF THE FILE

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import csv
import os
import time
from datetime import datetime
from typing import Optional, Set, List, Dict, Any, Callable, TYPE_CHECKING, Union
import queue # Moved queue import to global scope
from typing_extensions import TypeAlias

if TYPE_CHECKING:
    from can_communication import CanCommunication # ICanRawMessageProcessor is defined below
    # Attempt to import the actual can.Message for type checking if 'can' package is available
    try:
        from can import Message as CanMessage_Actual # Import the actual type
        CanGuiMessage: TypeAlias = CanMessage_Actual # Define TypeAlias if can is available
    except ImportError:
        CanGuiMessage: TypeAlias = Any # Fallback if 'can' package is not installed
else:
    # At runtime, CanGuiMessage is Any to avoid import errors if 'can' is not installed
    CanGuiMessage: TypeAlias = Any


# Define the interface here for clarity
class ICanRawMessageProcessor:
    def process_raw_can_message(self, msg: CanGuiMessage): # Use the defined TypeAlias
        raise NotImplementedError
    def is_interested(self, arbitration_id: int) -> bool:
        raise NotImplementedError

class CanExpert(ICanRawMessageProcessor):
    def __init__(self,
                 parent_frame: ttk.Frame,
                 can_comm: Optional[CanCommunication], # Forward reference for CanCommunication
                 gui_queue: queue.Queue, # Should be fine with global import and __future__ annotations
                 log_via_queue_callback: Callable[[str], None]):
        self.parent_frame = parent_frame
        self.can_comm = can_comm
        self.gui_queue = gui_queue
        self.log_g = log_via_queue_callback

        self.monitored_ids: Set[int] = set()
        self.is_monitoring: bool = False
        self.csv_log_buffer: List[Dict[str, Any]] = []
        self.csv_filename: Optional[str] = None
        self.csv_writer = None
        self.csv_file_handle = None

        # --- UI Elements ---
        self.id_send_var = tk.StringVar(value="7E0")
        self.data_send_var = tk.StringVar(value="02010D")
        self.is_remote_frame_var = tk.BooleanVar(value=False)
        self.ids_monitor_var = tk.StringVar(value="7E8")
        self.send_button: Optional[ttk.Button] = None
        self.monitor_toggle_button: Optional[ttk.Button] = None
        self.message_display: Optional[scrolledtext.ScrolledText] = None

        self._create_ui()

    def _log_internal(self, message: str):
        if callable(self.log_g):
            self.log_g(f"[CAN Expert] {message}")
        else:
            print(f"[CAN Expert Log Error] {message}")

    def _create_ui(self):
        # --- Send Frame ---
        send_frame = ttk.LabelFrame(self.parent_frame, text="Send Custom CAN Message", padding="10")
        send_frame.pack(fill=tk.X, padx=5, pady=5)
        send_frame.columnconfigure(1, weight=1)
        send_frame.columnconfigure(3, weight=2)

        ttk.Label(send_frame, text="CAN ID (Hex):").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        id_entry = ttk.Entry(send_frame, textvariable=self.id_send_var, width=10)
        id_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)

        ttk.Label(send_frame, text="Data (Hex):").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        data_entry = ttk.Entry(send_frame, textvariable=self.data_send_var, width=30)
        data_entry.grid(row=0, column=3, padx=5, pady=5, sticky=tk.EW)

        rtr_checkbutton = ttk.Checkbutton(send_frame, text="RTR", variable=self.is_remote_frame_var)
        rtr_checkbutton.grid(row=0, column=4, padx=(10,5), pady=5, sticky=tk.W)

        self.send_button = ttk.Button(send_frame, text="Send Message", command=self._handle_send_message, state=tk.DISABLED)
        self.send_button.grid(row=0, column=5, padx=10, pady=5, sticky=tk.E)


        # --- Monitor Frame ---
        monitor_frame = ttk.LabelFrame(self.parent_frame, text="Monitor CAN Responses", padding="10")
        monitor_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        monitor_frame.columnconfigure(1, weight=1)

        monitor_controls_frame = ttk.Frame(monitor_frame)
        monitor_controls_frame.pack(fill=tk.X, pady=(0,5))
        monitor_controls_frame.columnconfigure(1, weight=1)

        ttk.Label(monitor_controls_frame, text="Monitor IDs (Hex, comma-sep):").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        monitor_ids_entry = ttk.Entry(monitor_controls_frame, textvariable=self.ids_monitor_var)
        monitor_ids_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)

        self.monitor_toggle_button = ttk.Button(monitor_controls_frame, text="Start Monitoring", command=self._handle_toggle_monitoring, state=tk.DISABLED)
        self.monitor_toggle_button.grid(row=0, column=2, padx=5, pady=5, sticky=tk.E)

        clear_display_button = ttk.Button(monitor_controls_frame, text="Clear Display", command=self._clear_display_area)
        clear_display_button.grid(row=0, column=3, padx=5, pady=5, sticky=tk.E)

        display_text_frame = ttk.Frame(monitor_frame)
        display_text_frame.pack(fill=tk.BOTH, expand=True, pady=(5,0))
        self.message_display = scrolledtext.ScrolledText(display_text_frame, height=15, width=80, state=tk.DISABLED, wrap=tk.WORD, font=("Consolas", 9))
        self.message_display.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar = ttk.Scrollbar(display_text_frame, orient=tk.VERTICAL, command=self.message_display.yview)
        self.message_display['yscrollcommand'] = scrollbar.set
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def update_connection_status(self, connected: bool):
        new_state = tk.NORMAL if connected else tk.DISABLED
        if self.send_button:
            self.send_button.config(state=new_state)
        if self.monitor_toggle_button:
            if connected:
                self.monitor_toggle_button.config(state=tk.NORMAL)
            else:
                if self.is_monitoring:
                    self._stop_monitoring_logic()
                self.monitor_toggle_button.config(state=tk.DISABLED, text="Start Monitoring")


    def _handle_send_message(self):
        if not self.can_comm or not self.can_comm.is_connected:
            messagebox.showerror("Error", "CAN bus not connected.", parent=self.parent_frame)
            return

        can_id_str = self.id_send_var.get().strip()
        can_data_str = self.data_send_var.get().strip().replace(" ", "")

        try:
            arbitration_id = int(can_id_str, 16)
            if not (0 <= arbitration_id <= 0x7FF) and not (0 <= arbitration_id <= 0x1FFFFFFF): # Basic check for std/ext
                 raise ValueError("CAN ID out of range for standard or extended.")
        except ValueError:
            messagebox.showerror("Input Error", f"Invalid CAN ID: '{can_id_str}'. Must be hex.", parent=self.parent_frame)
            return

        data_bytes: bytes = b'' # Ensure data_bytes is initialized
        try:
            if can_data_str: # Only attempt conversion if string is not empty
                data_bytes = bytes.fromhex(can_data_str)
            if len(data_bytes) > 8:
                raise ValueError("Data length exceeds 8 bytes.")
        except ValueError as e:
            messagebox.showerror("Input Error", f"Invalid CAN Data: '{can_data_str}'. Must be hex, max 8 bytes. Error: {e}", parent=self.parent_frame)
            return
        
        is_extended = arbitration_id > 0x7FF
        is_remote = self.is_remote_frame_var.get() # Get RTR status from checkbox

        if is_remote and data_bytes:
            self._log_internal(f"Note: Sending Remote Frame (RTR=1). Data field ('{data_bytes.hex().upper()}') length will set requested DLC, but data itself is typically ignored by recipient for RTR.")
        elif is_remote and not data_bytes:
             self._log_internal(f"Note: Sending Remote Frame (RTR=1) with no data. Requested DLC will be 0.")

        self._log_internal(f"Sending: ID={arbitration_id:X}, Data='{data_bytes.hex().upper()}', Ext={is_extended}, RTR={is_remote}")
        
        # Ensure can_comm is available and has the send_custom_can_message method
        if self.can_comm and hasattr(self.can_comm, 'send_custom_can_message'):
            # The send_custom_can_message in can_communication.py needs to accept is_remote_frame
            success = self.can_comm.send_custom_can_message(arbitration_id, data_bytes, is_extended, is_remote)
            if success:
                self._log_internal("Custom message appears to have been sent by the bus layer.")
            else:
                self._log_internal("Bus layer reported failure to send custom message.")
                messagebox.showwarning("Send Error", "Failed to send CAN message. Check logs for details.", parent=self.parent_frame)
        else:
            self._log_internal("Error: CAN communication module not available or method missing for sending.")


    def _handle_toggle_monitoring(self):
        if self.is_monitoring:
            self._stop_monitoring_logic()
        else:
            self._start_monitoring_logic()

    def _start_monitoring_logic(self):
        if not self.can_comm or not self.can_comm.is_connected:
            messagebox.showerror("Error", "CAN bus not connected.", parent=self.parent_frame)
            return

        ids_str = self.ids_monitor_var.get().strip()
        if not ids_str:
            # Monitor all messages if no specific IDs are provided
            self.monitored_ids = set() # Empty set means all for is_interested
            self._log_internal("Starting monitoring for ALL CAN IDs.")
        else:
            try:
                parsed_ids = {int(id_val.strip(), 16) for id_val in ids_str.split(',') if id_val.strip()}
                self.monitored_ids = parsed_ids
                ids_hex_str = ", ".join(f"{id_val:X}" for id_val in sorted(list(self.monitored_ids)))
                self._log_internal(f"Starting monitoring for IDs: {ids_hex_str}")
            except ValueError:
                messagebox.showerror("Input Error", "Invalid format for Monitor IDs. Must be comma-separated hex values (e.g., 7E8, 1A0).", parent=self.parent_frame)
                return

        self.is_monitoring = True
        if self.monitor_toggle_button:
            self.monitor_toggle_button.config(text="Stop Monitoring")
        
        self.csv_log_buffer = [] # Clear previous buffer
        self._prepare_csv_log_file()

        if self.can_comm:
            self.can_comm.register_expert_raw_processor(self)

        self._log_internal("Monitoring started.")
        self._append_to_display("--- Monitoring Started ---")


    def _stop_monitoring_logic(self):
        self.is_monitoring = False
        if self.monitor_toggle_button:
            self.monitor_toggle_button.config(text="Start Monitoring")
        
        if self.can_comm:
            self.can_comm.register_expert_raw_processor(None) # Pass None to unregister

        self._log_internal("Monitoring stopped.")
        self._append_to_display("--- Monitoring Stopped ---")
        self._save_and_close_csv_log()


    def handle_stop_monitoring_on_disconnect(self):
        """Called when CAN disconnects to ensure monitoring stops cleanly."""
        if self.is_monitoring:
            self._log_internal("CAN disconnected, stopping expert monitoring automatically.")
            self._stop_monitoring_logic()


    def _prepare_csv_log_file(self):
        base_filename = "can_expert_log"
        extension = ".csv"
        counter = 1
        # Add a timestamp to the filename to make it unique for each session
        current_timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.csv_filename = f"{base_filename}_{current_timestamp_str}_{counter}{extension}"
        while os.path.exists(self.csv_filename): # Ensure unique filename
            counter += 1
            self.csv_filename = f"{base_filename}_{current_timestamp_str}_{counter}{extension}"
        
        try:
            self.csv_file_handle = open(self.csv_filename, 'w', newline='', encoding='utf-8')
            header = ['Timestamp', 'ID (Hex)', 'Extended', 'RTR', 'DLC', 'Data (Hex)'] # Added Extended and RTR
            self.csv_writer = csv.DictWriter(self.csv_file_handle, fieldnames=header)
            self.csv_writer.writeheader()
            self._log_internal(f"Opened CSV log file: {self.csv_filename}")
        except IOError as e:
            self._log_internal(f"Error opening CSV log file '{self.csv_filename}': {e}")
            messagebox.showerror("CSV Error", f"Could not open CSV log file: {e}", parent=self.parent_frame)
            self.csv_filename = None
            self.csv_writer = None
            self.csv_file_handle = None


    def _save_and_close_csv_log(self):
        if self.csv_file_handle: # Check if file was successfully opened
            try:
                self.csv_file_handle.close()
                self._log_internal(f"Closed CSV log file: {self.csv_filename}")
            except Exception as e:
                self._log_internal(f"Error closing CSV file: {e}")
        
        self.csv_writer = None # Clear writer
        self.csv_file_handle = None # Clear file handle
        # self.csv_filename remains for information if needed

    def _append_to_display(self, text_line: str):
        """Appends a line of text to the message display area via GUI queue."""
        if self.message_display and self.gui_queue: # Ensure gui_queue is available
            self.gui_queue.put(("can_expert_display_update", text_line))

    def _clear_display_area(self):
        if self.message_display:
            self.message_display.config(state=tk.NORMAL)
            self.message_display.delete('1.0', tk.END)
            self.message_display.config(state=tk.DISABLED)
        self._log_internal("CAN Expert display cleared.")

    # --- ICanRawMessageProcessor Implementation ---
    def is_interested(self, arbitration_id: int) -> bool:
        if not self.is_monitoring:
            return False
        if not self.monitored_ids: # If empty, interested in all
            return True
        return arbitration_id in self.monitored_ids

    def process_raw_can_message(self, msg: CanGuiMessage): # Use the defined TypeAlias
        if not self.is_monitoring:
            return

        # Gracefully access attributes from the message object, providing defaults
        ts = getattr(msg, 'timestamp', time.time()) # Default to current time if not present
        arb_id = getattr(msg, 'arbitration_id', 0)
        is_ext = getattr(msg, 'is_extended_id', False)
        is_rtr = getattr(msg, 'is_remote_frame', False)
        dlc_val = getattr(msg, 'dlc', 0)
        data_val = getattr(msg, 'data', b'') # Default to empty bytes

        timestamp_str = datetime.fromtimestamp(ts).isoformat(sep=' ', timespec='milliseconds')
        id_hex = f"{arb_id:X}"
        data_hex = data_val.hex().upper()

        # Updated display line to include Extended and RTR flags
        display_line = f"{timestamp_str} | ID: {id_hex.ljust(8)} | Ext: {is_ext} | RTR: {is_rtr} | DLC: {dlc_val} | Data: {data_hex}"
        self._append_to_display(display_line)

        log_entry = {
            'Timestamp': timestamp_str,
            'ID (Hex)': id_hex,
            'Extended': is_ext, # Log Extended ID flag
            'RTR': is_rtr,      # Log Remote Frame flag
            'DLC': dlc_val,
            'Data (Hex)': data_hex
        }
        
        if self.csv_writer and self.csv_file_handle:
            try:
                self.csv_writer.writerow(log_entry)
                self.csv_file_handle.flush() # Ensure data is written to disk periodically
            except Exception as e:
                self._log_internal(f"Error writing to CSV in real-time: {e}")
                # Consider how to handle persistent CSV errors (e.g., stop logging, try to reopen)
