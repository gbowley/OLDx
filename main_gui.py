# main_gui.py
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog
import threading
import queue
import time
from datetime import datetime
import traceback
import logging
from typing import Optional, Dict, Any
import re # For VIN validation
import os # For checking log file existence and icon path
import csv # For CSV export

# Import local modules
try:
    from can_communication import CanCommunication, ILiveDataProcessor
    from vin_logic import lookup_vehicle_info
    from diagnostics import get_faults, clear_faults, get_performance_data, get_vin 
    from live_dashboard import LiveDashboard, BROADCAST_LIVE_DATA_IDS, OBD_MODE_01_PIDS_TO_REQUEST, MODE_22_PIDS_TO_REQUEST
    from known_faults import FAULTS_CONFIRMED, FAULTS_PENDING
    from log_data import mode22_live_data
except ImportError as e:
     print(f"Fatal Error importing local modules: {e}"); exit(f"Import Error: {e}")
except Exception as e:
     print(f"Unexpected import error: {e}"); exit("Initialization Error")

# Basic VIN validation regex (17 alphanumeric chars, excluding I, O, Q)
VIN_REGEX = re.compile(r"^[A-HJ-NPR-Z0-9]{17}$", re.IGNORECASE)

# Global request update frequency options (does not affect CAN listened polling which is ~17hz)
UPDATE_FREQUENCIES = {
    "Hyperfast (75 ms)": 0.075,
    "Faster (100 ms)": 0.1,
    "Fast (125 ms)": 0.125,
    "Medium (250 ms)": 0.25,
    "Slow (500 ms)": 0.5,
}

# Define keys for the vehicle info section to avoid typos
# Note: 'Model' is kept separate as it remains in the top frame
VEHICLE_DETAIL_KEYS = [
    "Vehicle_Type", "Model_Year", "Market",
    "ECU_Program", "TCU_Program", "ABS_Program", "ABS_Module",
    "TPMS", "SRS", "IP", "Comment"
]

class CarDiagnosticsApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Open Lotus Diagnostics")
        self.root.minsize(900, 850)

        # --- Set Application Icon ---
        icon_path = 'oldx.ico'
        if os.path.exists(icon_path):
            try:
                if os.name == 'nt':
                    self.root.iconbitmap(icon_path)
            except Exception as e:
                print(f"Warning: Could not set application icon '{icon_path}': {e}")
        else:
            print(f"Warning: Application icon '{icon_path}' not found.")
        # --- End Icon Setting ---

        self.can_comm: Optional[CanCommunication] = None; self.live_dashboard: Optional[LiveDashboard] = None
        self.gui_queue = queue.Queue()
        self.current_vin: Optional[str] = None; self.vehicle_info: Optional[Dict[str, Any]] = None
        self.update_frequency_var = tk.DoubleVar(value=1.0)
        self.all_dashboard_keys = set()

        # --- Vehicle Info StringVars ---
        self.vin_display_var = tk.StringVar(value="---")
        # Model stays in the top frame's vars
        self.model_display_var = tk.StringVar(value="---")
        self.vehicle_detail_vars: Dict[str, tk.StringVar] = {}
        for key in VEHICLE_DETAIL_KEYS:
            self.vehicle_detail_vars[key] = tk.StringVar(value="---")
        # --- End Vehicle Info StringVars ---

        # Styling
        style = ttk.Style(); available_themes = style.theme_names(); preferred_themes = ['vista', 'xpnative', 'win10', 'aqua', 'clam']
        theme_to_use = 'clam';
        for theme in preferred_themes:
             if theme in available_themes: theme_to_use = theme; break
        try: style.theme_use(theme_to_use)
        except tk.TclError: print(f"Warn: Theme '{theme_to_use}' not found.")

        # --- Top Connection Frame ---
        conn_frame = ttk.LabelFrame(root, text="Connection", padding="10"); conn_frame.pack(fill=tk.X, padx=10, pady=(10,5))
        conn_frame.columnconfigure(1, weight=1)
        conn_frame.columnconfigure(3, weight=1)
        conn_frame.columnconfigure(5, weight=0)
        conn_frame.columnconfigure(6, weight=0)
        conn_frame.columnconfigure(7, weight=3)

        ttk.Label(conn_frame, text="Interface:").grid(row=0, column=0, padx=(0,5), pady=5, sticky=tk.W)
        self.iface_var = tk.StringVar(value="usb2can"); all_interfaces = ["usb2can"]
        self.iface_combo = ttk.Combobox(conn_frame, textvariable=self.iface_var, width=10, values=all_interfaces, state='readonly'); self.iface_combo.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)

        ttk.Label(conn_frame, text="Channel:").grid(row=0, column=2, padx=(10,5), pady=5, sticky=tk.W)
        self.channel_entry = ttk.Entry(conn_frame, width=12); self.channel_entry.insert(0, ""); self.channel_entry.grid(row=0, column=3, padx=5, pady=5, sticky=tk.EW)

        ttk.Label(conn_frame, text="Bitrate:").grid(row=0, column=4, padx=(10,5), pady=5, sticky=tk.W)
        self.bitrate_var = tk.StringVar(value="500000"); bitrate_values = ["1000000", "500000"]
        self.bitrate_combo = ttk.Combobox(conn_frame, textvariable=self.bitrate_var, width=8, values=bitrate_values); self.bitrate_combo.grid(row=0, column=5, padx=5, pady=5, sticky=tk.W)

        self.connect_button = ttk.Button(conn_frame, text="Connect", command=self.toggle_connection, width=12);
        self.connect_button.grid(row=0, column=6, padx=(20, 5), pady=5, sticky=tk.E)

        self.status_label = ttk.Label(conn_frame, text="Status: Disconnected", foreground="red", font=('Segoe UI', 10, 'bold'), anchor=tk.E)
        self.status_label.grid(row=0, column=7, padx=(5, 0), pady=5, sticky=tk.EW)

        # --- Vehicle Info Frame ---
        vin_frame = ttk.LabelFrame(root, text="Vehicle Identification", padding="10"); vin_frame.pack(fill=tk.X, padx=10, pady=5)
        # Configure columns for desired spacing
        vin_frame.columnconfigure(0, weight=0)
        vin_frame.columnconfigure(2, weight=1)
        vin_frame.columnconfigure(4, weight=2)

        # Button first
        self.get_vin_button = ttk.Button(vin_frame, text="Get VIN / Identify", command=self.get_vin_action, state=tk.DISABLED)
        self.get_vin_button.grid(row=0, column=0, padx=(0, 10), pady=5, sticky=tk.W)

        # VIN Label and Entry next
        ttk.Label(vin_frame, text="VIN:").grid(row=0, column=1, padx=(0, 5), pady=5, sticky=tk.E)
        vin_display_entry = ttk.Entry(vin_frame, textvariable=self.vin_display_var, state='readonly', width=25)
        vin_display_entry.grid(row=0, column=2, padx=(0, 10), pady=5, sticky=tk.EW)

        # Model Label and Display last
        ttk.Label(vin_frame, text="Model:").grid(row=0, column=3, padx=(0, 5), pady=5, sticky=tk.E)
        model_display_label = ttk.Label(vin_frame, textvariable=self.model_display_var, anchor=tk.W, relief=tk.SUNKEN, borderwidth=1, background="white")
        model_display_label.grid(row=0, column=4, padx=(0, 0), pady=5, sticky=tk.EW) # Label expands

        # --- Notebook ---
        self.notebook = ttk.Notebook(root, padding="5"); self.notebook.pack(expand=True, fill=tk.BOTH, padx=5, pady=(0,5))
        self.faults_frame = ttk.Frame(self.notebook, padding="10"); self.notebook.add(self.faults_frame, text=' Diagnostics & Faults '); self.create_faults_tab()
        self.vehicle_details_frame = ttk.Frame(self.notebook, padding="10"); self.notebook.add(self.vehicle_details_frame, text=' Vehicle Details '); self.create_vehicle_details_tab()
        self.dashboard_frame = ttk.Frame(self.notebook, padding="10"); self.notebook.add(self.dashboard_frame, text=' Live Dashboard '); self.create_dashboard_tab()
        self.perf_frame = ttk.Frame(self.notebook, padding="10"); self.notebook.add(self.perf_frame, text=' Performance Data '); self.create_performance_tab()
        self.log_frame = ttk.Frame(self.notebook, padding="10"); self.notebook.add(self.log_frame, text=' Log '); self.create_log_tab()

        self.set_connected_state_buttons(False); self.root.after(100, self.process_gui_queue)

    # --- Vehicle Details ---
    def create_vehicle_details_tab(self):
        details_frame = self.vehicle_details_frame
        details_frame.columnconfigure(1, weight=1)
        details_frame.columnconfigure(3, weight=1)

        def add_info_row(row_index, key1, label1, key2, label2):
            ttk.Label(details_frame, text=label1 + ":").grid(row=row_index, column=0, padx=5, pady=3, sticky=tk.E)
            ttk.Label(details_frame, textvariable=self.vehicle_detail_vars[key1], anchor=tk.W, relief=tk.SUNKEN, borderwidth=1, background="white", wraplength=200).grid(row=row_index, column=1, padx=5, pady=3, sticky=tk.EW)
            ttk.Label(details_frame, text=label2 + ":").grid(row=row_index, column=2, padx=5, pady=3, sticky=tk.E)
            ttk.Label(details_frame, textvariable=self.vehicle_detail_vars[key2], anchor=tk.W, relief=tk.SUNKEN, borderwidth=1, background="white", wraplength=200).grid(row=row_index, column=3, padx=5, pady=3, sticky=tk.EW)

        def add_info_row_single(row_index, key1, label1, columnspan=3):
             ttk.Label(details_frame, text=label1 + ":").grid(row=row_index, column=0, padx=5, pady=3, sticky=tk.E)
             ttk.Label(details_frame, textvariable=self.vehicle_detail_vars[key1], anchor=tk.W, relief=tk.SUNKEN, borderwidth=1, background="white", wraplength=400).grid(row=row_index, column=1, columnspan=columnspan, padx=5, pady=3, sticky=tk.EW)


        # Add rows for vehicle details (using VEHICLE_DETAIL_KEYS)
        add_info_row(0, "Vehicle_Type", "Type",       "Model_Year", "Year")
        add_info_row(1, "Market",        "Market",      "ECU_Program", "ECU Pgm")
        add_info_row(2, "TCU_Program",  "TCU Pgm",    "ABS_Program","ABS Pgm")
        add_info_row(3, "ABS_Module",  "ABS Mod",    "SRS", "SRS Mod")
        add_info_row(4, "TPMS",           "TPMS",       "IP",       "IP Mod")
        add_info_row_single(5, "Comment", "Comment", columnspan=3) # Comment spans cols 1, 2, 3


    # --- Logging ---
    def create_log_tab(self):
        log_controls = ttk.Frame(self.log_frame); log_controls.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(log_controls, text="Log:").pack(side=tk.LEFT, anchor=tk.W)
        ttk.Button(log_controls, text="Clear Log", command=self.clear_log).pack(side=tk.RIGHT)
        text_frame = ttk.Frame(self.log_frame); text_frame.pack(expand=True, fill=tk.BOTH)
        self.log_text = scrolledtext.ScrolledText(text_frame, height=20, width=90, state=tk.DISABLED, wrap=tk.WORD, font=("Consolas", 9))
        self.log_text.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)
        scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text['yscrollcommand'] = scrollbar.set; scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def _update_log_widget(self, message): # Runs in GUI thread
        try: now = datetime.now().strftime("%H:%M:%S.%f")[:-3]; self.log_text.config(state=tk.NORMAL); self.log_text.insert(tk.END, f"{now} - {message}\n"); self.log_text.see(tk.END); self.log_text.config(state=tk.DISABLED)
        except Exception as e: print(f"Log GUI Error: {e}")

    def log_via_queue(self, message: str): # Called from any thread
        try: self.gui_queue.put(("log", str(message)))
        except Exception as e: print(f"LOG (queue error: {e}): {message}")

    def clear_log(self): # Runs in GUI thread
        try: self.log_text.config(state=tk.NORMAL); self.log_text.delete('1.0', tk.END); self.log_text.config(state=tk.DISABLED); self.log_via_queue("Log cleared.")
        except Exception as e: print(f"Error clearing log: {e}")

    # --- Connection Handling ---
    def update_status_label(self, text: str, color: str):
        try: self.status_label.config(text=f"Status: {text}", foreground=color)
        except Exception as e: print(f"Status Label Error: {e}")

    def toggle_connection(self):
        if self.can_comm and self.can_comm.is_connected: self.disconnect_can()
        else: self.connect_can()

    def connect_can(self):
        iface = self.iface_var.get(); channel = self.channel_entry.get().strip(); bitrate_str = self.bitrate_var.get()
        if not iface: messagebox.showerror("Input Error", "Select interface.", parent=self.root); return
        import sys
        if sys.platform == "win32" and iface == "usb2can" and not channel: messagebox.showwarning("Channel Required", "'usb2can' needs Serial Number in 'Channel'. Auto-detect may fail.", parent=self.root)
        if not bitrate_str: messagebox.showerror("Input Error", "Select bitrate.", parent=self.root); return
        try: bitrate = int(bitrate_str); assert bitrate > 0
        except (ValueError, AssertionError): messagebox.showerror("Invalid Bitrate", f"Bitrate '{bitrate_str}' not valid.", parent=self.root); return
        self.log_via_queue(f"Connecting: {iface}, Chan='{channel}', Rate={bitrate}...")
        self.update_status_label("Connecting...", "orange")
        self.connect_button.config(text="Connecting...", state=tk.DISABLED)
        self.iface_combo.config(state=tk.DISABLED); self.channel_entry.config(state=tk.DISABLED); self.bitrate_combo.config(state=tk.DISABLED)
        threading.Thread(target=self._connect_thread, args=(iface, channel, bitrate, self.gui_queue), daemon=True).start()

    def _connect_thread(self, iface, channel, bitrate, gui_queue_ref):
        log_func = lambda msg: gui_queue_ref.put(("log", msg)); status_func = lambda data: gui_queue_ref.put(("status", data)); reenable_func = lambda result: gui_queue_ref.put(("reenable_connect_button", result))
        can_comm_instance = None; live_dash_instance = None; connection_successful = False
        local_can_comm = None; local_live_dashboard = None
        try:
            can_comm_instance = CanCommunication(channel=channel if channel else None, gui_queue=gui_queue_ref, interface=iface, bitrate=bitrate)
            if can_comm_instance.connect():
                connection_successful = True; status_func({'text': "Connected", 'color': "green"})
                local_can_comm = can_comm_instance
                try:
                     log_func("Connection established. Waiting 0.5s before enabling functions...")
                     time.sleep(0.5)
                     current_freq = self.update_frequency_var.get()
                     live_dash_instance = LiveDashboard(
                         can_comm_instance,
                         lambda data: gui_queue_ref.put(("live_data", data)),
                         target_ids=None,
                         update_interval=current_freq
                     )
                     can_comm_instance.register_live_dashboard_processor(live_dash_instance)
                     local_live_dashboard = live_dash_instance
                except Exception as ld_e: log_func(f"Error init LiveDashboard: {ld_e}")
                self.can_comm = local_can_comm
                self.live_dashboard = local_live_dashboard
            else: status_func({'text': "Connection Failed", 'color': "red"}); self.can_comm = None; self.live_dashboard = None
        except Exception as thread_e: log_func(f"Connect thread error: {thread_e}\n{traceback.format_exc()}"); status_func({'text': "Thread Error", 'color': "red"}); self.can_comm = None; self.live_dashboard = None
        finally: reenable_func(connection_successful)

    def disconnect_can(self):
        self.connect_button.config(text="Disconnecting...", state=tk.DISABLED); self.log_via_queue("Disconnect request...")
        threading.Thread(target=self._disconnect_thread, daemon=True).start()

    def _disconnect_thread(self):
        current_live_dashboard = self.live_dashboard
        if current_live_dashboard and current_live_dashboard.running: self.log_via_queue("Stopping dashboard..."); current_live_dashboard.stop()
        current_can_comm = self.can_comm
        if current_can_comm:
             self.log_via_queue("Unregistering processor...");
             if hasattr(current_can_comm, 'register_live_dashboard_processor'): current_can_comm.register_live_dashboard_processor(None)
             self.log_via_queue("Shutting down CAN..."); current_can_comm.disconnect()
        else: self.log_via_queue("Disconnect: No active connection.")
        self.gui_queue.put(("status", {'text': "Disconnected", 'color': "red"})); self.gui_queue.put(("reenable_connect_button", False)); self.gui_queue.put(("clear_instances", None))

    def set_connected_state_buttons(self, connected: bool):
        action_button_state = tk.NORMAL if connected else tk.DISABLED; input_state = tk.DISABLED if connected else tk.NORMAL
        try:
            self.iface_combo.config(state=input_state if input_state == tk.NORMAL else 'readonly'); self.channel_entry.config(state=input_state); self.bitrate_combo.config(state=input_state)
            if hasattr(self, 'get_vin_button'): self.get_vin_button.config(state=action_button_state)
            if hasattr(self, 'read_faults_button'): self.read_faults_button.config(state=action_button_state)
            if hasattr(self, 'clear_faults_button'): self.clear_faults_button.config(state=action_button_state)
            if hasattr(self, 'start_dash_button'): self.start_dash_button.config(state=action_button_state)
            if hasattr(self, 'stop_dash_button'):
                stop_state = tk.DISABLED;
                if connected and self.live_dashboard and self.live_dashboard.running:
                    stop_state = tk.NORMAL
                self.stop_dash_button.config(state=stop_state)
            if hasattr(self, 'read_perf_button'): self.read_perf_button.config(state=action_button_state)
            if hasattr(self, 'freq_combo'): self.freq_combo.config(state=input_state if input_state == tk.NORMAL else 'readonly')
        except tk.TclError: pass
        except Exception as e: print(f"Button state error: {e}")

    # --- VIN / Vehicle Info Handling ---
    def get_vin_action(self):
        if not self.can_comm or not self.can_comm.is_connected: messagebox.showerror("Error", "Not connected.", parent=self.root); return
        self.log_via_queue("Attempting to retrieve VIN..."); self.get_vin_button.config(state=tk.DISABLED)
        self.vin_display_var.set("Reading...")
        self.model_display_var.set("---") # Clear model specifically
        for key in VEHICLE_DETAIL_KEYS: # Clear details in the other tab
            self.vehicle_detail_vars[key].set("---")
        self.vehicle_info = None
        threading.Thread(target=self._get_vin_thread, daemon=True).start()

    def _get_vin_thread(self):
        vin_str = None; vehicle_data = None; request_manual = False
        try:
            current_can_comm = self.can_comm
            if current_can_comm and current_can_comm.is_connected:
                vin_str = get_vin(current_can_comm, self.log_via_queue)
                if vin_str:
                    self.log_via_queue(f"VIN Read OK: {vin_str}")
                    vehicle_data = lookup_vehicle_info(vin_str)
                    if vehicle_data: self.log_via_queue(f"Vehicle ID: {vehicle_data.get('Model_Year')} {vehicle_data.get('Model')}")
                    else: self.log_via_queue(f"VIN {vin_str} read, but model unknown in database.")
                else:
                    self.log_via_queue("Failed to automatically read VIN. Requesting manual input.")
                    request_manual = True
            else: self.log_via_queue("Error: CAN comms unavailable in get_vin thread.")
        except Exception as e: self.log_via_queue(f"Exception during VIN task: {e}\n{traceback.format_exc()}")
        finally:
            if not request_manual:
                self.gui_queue.put(("vehicle_info_update", {'vin': vin_str, 'vehicle': vehicle_data}))
            else:
                self.gui_queue.put(("request_manual_vin", None))

    def _handle_request_manual_vin(self, data=None): # Runs in GUI thread
        self.log_via_queue("Displaying manual VIN entry dialog...")
        manual_vin = simpledialog.askstring("Manual VIN Entry",
                                            "Automatic VIN read failed.\nPlease enter the 17-character VIN manually:",
                                            parent=self.root)
        vehicle_data = None
        vin_to_use = None
        if manual_vin:
            manual_vin = manual_vin.strip().upper()
            if VIN_REGEX.match(manual_vin):
                self.log_via_queue(f"Manual VIN entered: {manual_vin}. Looking up vehicle info...")
                vin_to_use = manual_vin
                vehicle_data = lookup_vehicle_info(vin_to_use)
                if vehicle_data:
                    self.log_via_queue(f"Vehicle ID from manual VIN: {vehicle_data.get('Model_Year')} {vehicle_data.get('Model')}")
                else:
                    self.log_via_queue(f"Manual VIN {vin_to_use} valid format, but model unknown in database.")
            else:
                self.log_via_queue(f"Invalid VIN format entered manually: '{manual_vin}'.")
                messagebox.showerror("Invalid VIN", "The entered VIN is not valid (must be 17 alphanumeric characters, excluding I, O, Q).", parent=self.root)
                vin_to_use = "Manual Entry Invalid"
        else:
            self.log_via_queue("Manual VIN entry cancelled by user.")
            vin_to_use = "Manual Entry Cancelled"
        self.gui_queue.put(("vehicle_info_update", {'vin': vin_to_use, 'vehicle': vehicle_data}))

    def _handle_vehicle_info_update(self, update_data): # Runs in GUI thread
        vin_str = update_data.get('vin')
        vehicle_data = update_data.get('vehicle')

        self.current_vin = vin_str if vin_str and "Manual Entry" not in vin_str and "Error Reading" not in vin_str else None
        self.vehicle_info = vehicle_data

        self.vin_display_var.set(vin_str if vin_str else "Error Reading VIN")

        if vehicle_data:
            # Set Model in the top frame
            model_value = vehicle_data.get("Model", "---")
            model_str = f"{vehicle_data.get('Model_Year','')} {model_value if model_value else 'Unknown'} ({vehicle_data.get('Market', '')})"
            self.model_display_var.set(model_str.strip())

            # Set all other details in the details tab vars
            for key in VEHICLE_DETAIL_KEYS:
                value = vehicle_data.get(key, "---")
                if self.vehicle_detail_vars.get(key):
                     self.vehicle_detail_vars[key].set(str(value) if value else "---")
            self.log_via_queue("Vehicle information updated.")
        else:
            # Clear Model and all detail fields
            self.model_display_var.set("---")
            for key in VEHICLE_DETAIL_KEYS:
                if self.vehicle_detail_vars.get(key):
                    self.vehicle_detail_vars[key].set("---")

            if self.current_vin: # If VIN was read but no match found
                self.model_display_var.set("Vehicle data not found")
                self.log_via_queue(f"VIN {self.current_vin} read, but no matching vehicle data found.")
            else:
                 self.log_via_queue("VIN read/entry failed, clearing vehicle info.")

        self.action_reenable_vin_button() # Re-enable button after update

    def action_reenable_vin_button(self, data=None): # Runs in GUI thread
         if hasattr(self, 'get_vin_button'):
             current_state = tk.NORMAL if self.can_comm and self.can_comm.is_connected else tk.DISABLED
             try:
                 self.get_vin_button.config(state=current_state)
             except tk.TclError: pass

    # --- Faults Tab ---
    def create_faults_tab(self):
        button_frame = ttk.Frame(self.faults_frame); button_frame.pack(fill=tk.X, pady=5)
        self.read_faults_button = ttk.Button(button_frame, text="Read All Faults", command=self.read_faults_action, state=tk.DISABLED); self.read_faults_button.pack(side=tk.LEFT, padx=5)
        self.clear_faults_button = ttk.Button(button_frame, text="Clear All Faults", command=self.clear_faults_action, state=tk.DISABLED); self.clear_faults_button.pack(side=tk.LEFT, padx=5)
        ttk.Label(self.faults_frame, text="Detected Faults (DTCs):").pack(anchor=tk.W, pady=(10, 2))
        list_frame = ttk.Frame(self.faults_frame); list_frame.pack(expand=True, fill=tk.BOTH, pady=(0,5))
        self.faults_list = tk.Listbox(list_frame, height=15, width=90, font=("Consolas", 9), selectmode=tk.EXTENDED)
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.faults_list.yview); self.faults_list.config(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y); self.faults_list.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)

    def read_faults_action(self):
        if not self.can_comm or not self.can_comm.is_connected: messagebox.showerror("Error", "Not connected.", parent=self.root); return
        self.faults_list.delete(0, tk.END); self.faults_list.insert(tk.END, "Reading faults (using vehicle info if available)...")
        self.read_faults_button.config(state=tk.DISABLED); self.clear_faults_button.config(state=tk.DISABLED)
        threading.Thread(target=self._read_faults_thread, daemon=True).start()

    def _read_faults_thread(self):
        fault_results = None
        try:
            current_can_comm = self.can_comm
            if current_can_comm and current_can_comm.is_connected:
                fault_results = get_faults(current_can_comm, self.log_via_queue, self.vehicle_info)
            else: self.log_via_queue("Error: CAN comms unavailable in read thread.")
        except Exception as e: self.log_via_queue(f"Exception reading faults: {e}\n{traceback.format_exc()}")
        finally: self.gui_queue.put(("faults_result", fault_results)); self.gui_queue.put(("reenable_faults_buttons", None))

    def display_faults(self, fault_data):
        self.faults_list.delete(0, tk.END); line_count = 0; has_actual_faults = False
        if fault_data is None: self.faults_list.insert(tk.END, "Error during fault reading."); self.faults_list.itemconfig(tk.END, {'fg': 'red'}); return
        if not fault_data: self.faults_list.insert(tk.END, "No response/faults found."); return
        for module in sorted(fault_data.keys()):
            messages = fault_data[module]
            if messages:
                self.faults_list.insert(tk.END, f"--- {module} ---"); self.faults_list.itemconfig(line_count, {'fg': 'navy'}); line_count += 1
                for msg in messages:
                    self.faults_list.insert(tk.END, f"  {msg}"); is_error_msg = "error" in msg.lower() or "response" in msg.lower() or "no fault" in msg.lower() or "skipped" in msg.lower() or "failure" in msg.lower(); is_no_faults = "No faults found" in msg or "No active faults" in msg
                    if not is_error_msg and not is_no_faults: self.faults_list.itemconfig(line_count, {'fg': 'red'}); has_actual_faults = True
                    elif is_no_faults: self.faults_list.itemconfig(line_count, {'fg': 'darkgreen'})
                    else: self.faults_list.itemconfig(line_count, {'fg': 'black'})
                    line_count += 1
                self.faults_list.insert(tk.END, ""); line_count += 1
        if not has_actual_faults and line_count > 0: self.faults_list.insert(tk.END, ">>> No active faults reported by responding/queried modules. <<<"); self.faults_list.itemconfig(tk.END, {'fg': 'green'})
        elif line_count == 0: self.faults_list.insert(tk.END, "No data received.")

    def clear_faults_action(self):
        if not self.can_comm or not self.can_comm.is_connected: messagebox.showerror("Error", "Not connected.", parent=self.root); return
        if not messagebox.askyesno("Confirm Clear", "Attempt to clear faults?\nRequires ignition cycle after.", parent=self.root): return
        self.log_via_queue("Starting fault clear..."); self.read_faults_button.config(state=tk.DISABLED); self.clear_faults_button.config(state=tk.DISABLED)
        threading.Thread(target=self._clear_faults_thread, daemon=True).start()

    def _clear_faults_thread(self):
        clear_results = None
        try:
             current_can_comm = self.can_comm
             if current_can_comm and current_can_comm.is_connected:
                 clear_results = clear_faults(current_can_comm, self.log_via_queue, self.vehicle_info)
             else: self.log_via_queue("Error: CAN comms unavailable in clear thread.")
        except Exception as e: self.log_via_queue(f"Exception clearing faults: {e}\n{traceback.format_exc()}")
        finally: self.gui_queue.put(("clear_faults_result", clear_results)); self.gui_queue.put(("reenable_faults_buttons", None)); self.log_via_queue("Clear finished. Re-read faults after ignition cycle.")

    def display_clear_results(self, clear_data):
        self.log_via_queue("--- Fault Clear Attempt Results ---")
        if clear_data is None: self.log_via_queue("  Clear process error."); return
        if not clear_data: self.log_via_queue("  Clear process no results."); return
        for module in sorted(clear_data.keys()):
            self.log_via_queue(f"  {module}:"); results = clear_data[module]
            if results: [self.log_via_queue(f"    {res}") for res in results]
            else: self.log_via_queue(f"    No result logged.")

    # --- Live Dashboard Tab ---
    def create_dashboard_tab(self):
        controls_frame = ttk.Frame(self.dashboard_frame)
        controls_frame.pack(fill=tk.X, pady=5)

        self.start_dash_button = ttk.Button(controls_frame, text="Start Dashboard", command=self.start_dashboard_action, state=tk.DISABLED)
        self.start_dash_button.pack(side=tk.LEFT, padx=5)
        self.stop_dash_button = ttk.Button(controls_frame, text="Stop Dashboard", command=self.stop_dashboard_action, state=tk.DISABLED)
        self.stop_dash_button.pack(side=tk.LEFT, padx=5)

        ttk.Label(controls_frame, text="Update Freq:").pack(side=tk.LEFT, padx=(20, 5))
        self.freq_combo = ttk.Combobox(controls_frame, values=list(UPDATE_FREQUENCIES.keys()), state='readonly', width=15)
        self.freq_combo.set("Medium (250 ms)")
        self.update_frequency_var.set(UPDATE_FREQUENCIES["Medium (250 ms)"])
        self.freq_combo.bind("<<ComboboxSelected>>", self.on_frequency_change)
        self.freq_combo.pack(side=tk.LEFT, padx=5)

        data_frame = ttk.LabelFrame(self.dashboard_frame, text="Live Data", padding="10")
        data_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        num_cols = 6
        label_width = 20
        value_width = 10

        self.dashboard_vars = {}
        row, col = 0, 0
        self.all_dashboard_keys.clear() # Clear keys before adding

        def add_dash_item(key, label_text):
            nonlocal row, col
            self.all_dashboard_keys.add(key) # Track all keys added to the UI
            formatted_label = label_text + ":"
            label_widget = ttk.Label(data_frame, text=formatted_label, anchor=tk.E, width=label_width)
            label_widget.grid(row=row, column=col*2, sticky=tk.E, padx=(5,0), pady=3)
            var = tk.StringVar(value="---")
            self.dashboard_vars[key] = var
            value_widget = ttk.Label(data_frame, textvariable=var, anchor=tk.W, width=value_width, relief=tk.SUNKEN, borderwidth=1, padding=(3,1), font=('Segoe UI', 9))
            value_widget.grid(row=row, column=col*2 + 1, sticky=tk.EW, padx=(0,10), pady=3)
            data_frame.columnconfigure(col*2 + 1, weight=1)
            col += 1
            if col >= num_cols:
                col = 0
                row += 1

        # Basic ECU/Cluster
        add_dash_item('rpm', 'RPM')
        add_dash_item('apps', 'Pedal Pos (%)')
        add_dash_item('throttlePos', 'Throttle Pos (%)')
        add_dash_item('maf', 'MAF (g/s)')
        add_dash_item('timingAdv', 'Timing Adv (deg)') # Overall Timing
        add_dash_item('gearAuto', 'Gear (Auto)')

        # Temperatures
        add_dash_item('coolant', 'Coolant Temp (C)')
        add_dash_item('iat', 'Intake Air Temp (C)') # No IAT on Exige??
        add_dash_item('aat', 'Ambient Air Temp (C)')

        # Fueling - Bank 1
        add_dash_item('lambdaB1', 'Lambda Bank 1')
        add_dash_item('stftB1', 'STFT Bank 1 (%)')
        add_dash_item('ltftB1', 'LTFT Bank 1 (%)')
        add_dash_item('fuelLearnDTB1', 'Fuel Learn DT B1 (us)')
        add_dash_item('fuelLearnZ2B1', 'Fuel Learn Z2 B1 (%)')
        add_dash_item('fuelLearnZ3B1', 'Fuel Learn Z3 B1 (%)')

        # Fueling - Bank 2
        add_dash_item('lambdaB2', 'Lambda Bank 2')
        add_dash_item('stftB2', 'STFT Bank 2 (%)')
        add_dash_item('ltftB2', 'LTFT Bank 2 (%)')
        add_dash_item('fuelLearnDTB2', 'Fuel Learn DT B2 (us)')
        add_dash_item('fuelLearnZ2B2', 'Fuel Learn Z2 B2 (%)')
        add_dash_item('fuelLearnZ3B2', 'Fuel Learn Z3 B2 (%)')

        # Knock Retard per Cylinder
        for i in range(1, 7):
            add_dash_item(f'knockCyl{i}', f'Knock Cyl {i} (deg)')

        # Switches / Status
        add_dash_item('brakeSwitch', 'Brake Switch')
        add_dash_item('sportSwitch', 'Sport Switch')
        add_dash_item('mil', 'MIL Lamp')
        add_dash_item('lowOilPressure', 'Low Oil Pressure')
        add_dash_item('fuelLevel', 'Fuel Level (%)')
        add_dash_item('tpmsFault', 'TPMS Fault')

        # ESP/ABS/ASR
        add_dash_item('espIntervention', 'ESP Intervention')
        add_dash_item('espAbsIntervention', 'ESP/ABS Interv')
        add_dash_item('espSystemState', 'ESP Sys State')
        add_dash_item('espAbsErrorState', 'ESP/ABS Error')
        add_dash_item('espAsrErrorState', 'ASR Error')
        add_dash_item('espErrorState', 'ESP Error State')

        # Cluster Misc
        add_dash_item('shiftLight1', 'Shift Light 1')
        add_dash_item('shiftLight2', 'Shift Light 2')
        add_dash_item('shiftLight3', 'Shift Light 3')
        add_dash_item('time', 'ECU Time')
        add_dash_item('textMessage', 'Cluster Text')

    def on_frequency_change(self, event=None):
        selected_text = self.freq_combo.get()
        new_freq = UPDATE_FREQUENCIES.get(selected_text, 1.0)
        self.update_frequency_var.set(new_freq)
        self.log_via_queue(f"Dashboard update frequency set to {new_freq} seconds.")
        if self.live_dashboard and self.live_dashboard.running:
            self.live_dashboard.set_update_interval(new_freq)

    def start_dashboard_action(self):
        if not self.can_comm or not self.can_comm.is_connected:
            messagebox.showerror("Error", "Connect first.", parent=self.root)
            return

        if not self.live_dashboard:
            try:
                current_freq = self.update_frequency_var.get()
                self.live_dashboard = LiveDashboard(
                    self.can_comm,
                    lambda data: self.gui_queue.put(("live_data", data)),
                    target_ids=None,
                    update_interval=current_freq
                )
                self.can_comm.register_live_dashboard_processor(self.live_dashboard)
                self.log_via_queue(f"Live Dashboard initialized (Update Freq: {current_freq}s).")
            except Exception as ld_e:
                messagebox.showerror("Error", f"Failed to initialize dashboard: {ld_e}", parent=self.root)
                self.live_dashboard = None
                return
        else:
            self.live_dashboard.clear_log_buffer() # Clear previous log
            self.log_via_queue("Cleared previous live data log buffer.")

        try:
             if self.live_dashboard.start():
                 self.log_via_queue("Live dashboard started.")
                 self.start_dash_button.config(state=tk.DISABLED)
                 self.stop_dash_button.config(state=tk.NORMAL)
                 self.freq_combo.config(state=tk.DISABLED)
                 for key in self.all_dashboard_keys:
                     if key in self.dashboard_vars:
                         self.dashboard_vars[key].set("...")
                     else:
                         print(f"Warning: Key '{key}' not found in dashboard_vars during start.")
             else:
                 self.log_via_queue("Dashboard start failed (already running or other issue).")
        except Exception as e:
             messagebox.showerror("Error", f"Start dashboard error: {e}", parent=self.root)
             self.log_via_queue(f"Start dashboard error: {e}")

    def stop_dashboard_action(self):
        if self.live_dashboard:
            saved_path = self.live_dashboard.save_log_to_csv()
            if saved_path:
                self.log_via_queue(f"Live data log saved to: {saved_path}")
            else:
                 self.log_via_queue("Live data log buffer was empty or failed to save.")

            self.live_dashboard.stop()
            self.log_via_queue("Live dashboard stopped.")
            self.start_dash_button.config(state=tk.NORMAL if self.can_comm and self.can_comm.is_connected else tk.DISABLED)
            self.stop_dash_button.config(state=tk.DISABLED)
            self.freq_combo.config(state='readonly')
            for key in self.dashboard_vars:
                self.dashboard_vars[key].set("---")
        else:
            self.log_via_queue("Stop dashboard: no instance.")

    def update_dashboard_values(self, data):
        if not isinstance(data, dict): print(f"Warn: Invalid dashboard update type: {type(data)}"); return
        for key, value in data.items():
            if key in self.dashboard_vars:
                var = self.dashboard_vars[key]; formatted_value = ""
                if value is None or value == "N/A":
                    formatted_value = "N/A"
                elif isinstance(value, float):
                    if key in ['rpm', 'coolant', 'fuelLevel', 'apps', 'throttlePos', 'maf', 'timingAdv', 'iat', 'aat'] or 'Timing' in key:
                         formatted_value = f"{value:.1f}"
                    elif 'Lambda' in key:
                         formatted_value = f"{value:.3f}"
                    elif 'FT' in key or 'Learn' in key:
                         formatted_value = f"{value:.2f}"
                    elif 'Knock' in key:
                         formatted_value = f"{value:.1f}"
                    else:
                         formatted_value = f"{value:.2f}"
                elif isinstance(value, int):
                    formatted_value = str(value)
                elif isinstance(value, bool):
                    formatted_value = "ON" if value else "OFF"
                else:
                    formatted_value = str(value)
                try:
                     if var.get() != formatted_value: var.set(formatted_value)
                except tk.TclError: pass
                except Exception as e: print(f"Error setting {key}: {e}")

    # --- Performance Data Tab ---
    def create_performance_tab(self):
        button_frame = ttk.Frame(self.perf_frame); button_frame.pack(fill=tk.X, pady=5)
        self.read_perf_button = ttk.Button(button_frame, text="Read Performance Data", command=self.read_performance_action, state=tk.DISABLED); self.read_perf_button.pack(side=tk.LEFT, padx=5)
        ttk.Label(self.perf_frame, text="ECU Performance Log Data:").pack(anchor=tk.W, pady=(10, 2))
        text_frame = ttk.Frame(self.perf_frame); text_frame.pack(expand=True, fill=tk.BOTH, pady=(0,5))
        self.perf_text = scrolledtext.ScrolledText(text_frame, height=20, width=90, state=tk.DISABLED, wrap=tk.WORD, font=("Consolas", 9))
        scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=self.perf_text.yview); self.perf_text['yscrollcommand'] = scrollbar.set
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y); self.perf_text.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)

    def read_performance_action(self):
        if not self.can_comm or not self.can_comm.is_connected: messagebox.showerror("Error", "Not connected.", parent=self.root); return
        self.perf_text.config(state=tk.NORMAL); self.perf_text.delete('1.0', tk.END); self.perf_text.insert('1.0', "Reading performance data...\n\n"); self.perf_text.config(state=tk.DISABLED)
        self.read_perf_button.config(state=tk.DISABLED)
        threading.Thread(target=self._read_performance_thread, daemon=True).start()

    def _read_performance_thread(self):
        perf_data = None
        try:
             current_can_comm = self.can_comm
             if current_can_comm and current_can_comm.is_connected: perf_data = get_performance_data(current_can_comm, self.log_via_queue)
             else: self.log_via_queue("Error: CAN comms unavailable in perf thread.")
        except Exception as e: self.log_via_queue(f"Exception reading perf data: {e}\n{traceback.format_exc()}")
        finally: self.gui_queue.put(("perf_data_result", perf_data)); self.gui_queue.put(("reenable_perf_button", None))

    def display_performance_data(self, perf_data):
        self.perf_text.config(state=tk.NORMAL); self.perf_text.delete('1.0', tk.END)
        if perf_data is None: self.perf_text.insert('1.0', "Error retrieving performance data."); self.perf_text.tag_add("error", "1.0", tk.END); self.perf_text.tag_config("error", foreground="red")
        elif not perf_data: self.perf_text.insert('1.0', "No performance data returned.")
        else:
            max_label_len = 0; non_header_keys = [k for k in perf_data if not k.startswith("---")]
            try: max_label_len = max(len(k) for k in non_header_keys) + 2 if non_header_keys else 30
            except ValueError: max_label_len = 30
            self.perf_text.tag_configure("header", font=("Segoe UI", 9, "bold"), foreground="navy"); self.perf_text.tag_configure("error_value", foreground="orange")
            for label, value in perf_data.items():
                 line_start = self.perf_text.index(tk.END + "-1c")
                 if label.startswith("---"): self.perf_text.insert(tk.END, f"\n{label}\n"); self.perf_text.tag_add("header", line_start + "+1l", tk.END + "-1l")
                 else:
                      formatted_line = f"{label:<{max_label_len}}: {value}\n"; self.perf_text.insert(tk.END, formatted_line)
                      if isinstance(value, str) and ("Error" in value or "Timeout" in value or "N/A" in value):
                           value_start_index = f"{line_start}+{max_label_len + 2}c"; self.perf_text.tag_add("error_value", value_start_index, tk.END + "-1l")
        self.perf_text.config(state=tk.DISABLED)

    # --- Re-enable Buttons Actions ---
    def action_reenable_connect_button(self, connection_successful: bool):
        self.connect_button.config(state=tk.NORMAL)
        if connection_successful: self.connect_button.config(text="Disconnect"); self.set_connected_state_buttons(True)
        else: self.connect_button.config(text="Connect"); self.set_connected_state_buttons(False)

    def action_clear_instances(self, data=None):
        self.can_comm = None; self.live_dashboard = None; self.log_via_queue("Internal comms instances cleared.")

    def action_reenable_faults_buttons(self, data=None):
        self.set_connected_state_buttons(self.can_comm and self.can_comm.is_connected)

    def action_reenable_perf_button(self, data=None):
        self.set_connected_state_buttons(self.can_comm and self.can_comm.is_connected)

    # --- GUI Queue Processing ---
    def _handle_status_update(self, data: Dict[str, str]):
         if isinstance(data, dict) and 'text' in data and 'color' in data: self.update_status_label(data['text'], data['color'])
         else: self.log_via_queue(f"Invalid status data: {data}")

    ACTION_MAP = {
        "log": _update_log_widget, "status": _handle_status_update,
        "faults_result": display_faults, "clear_faults_result": display_clear_results,
        "perf_data_result": display_performance_data, "live_data": update_dashboard_values,
        "reenable_connect_button": action_reenable_connect_button,
        "reenable_faults_buttons": action_reenable_faults_buttons,
        "reenable_perf_button": action_reenable_perf_button,
        "clear_instances": action_clear_instances,
        "vehicle_info_update": _handle_vehicle_info_update,
        "request_manual_vin": _handle_request_manual_vin,
    }

    def process_gui_queue(self):
        try:
            while True:
                action, data = self.gui_queue.get_nowait()
                handler = self.ACTION_MAP.get(action)
                if handler:
                    try: handler(self, data)
                    except Exception as e: print(f"GUI Error action '{action}': {e}"); self.log_via_queue(f"GUI Error action '{action}': {e}"); traceback.print_exc()
                else: print(f"Warning: No handler for GUI action '{action}'")
        except queue.Empty: pass
        except Exception as e: print(f"Critical error in process_gui_queue: {e}"); traceback.print_exc()
        finally:
            if hasattr(self.root, 'winfo_exists') and self.root.winfo_exists(): self.root.after(100, self.process_gui_queue)

    def on_closing(self):
        self.log_via_queue("Window closing signal received...")
        if self.live_dashboard and self.live_dashboard.running:
             self.log_via_queue("Stopping dashboard and saving log on close...")
             saved_path = self.live_dashboard.save_log_to_csv() # Attempt save
             if saved_path:
                 self.log_via_queue(f"Live data log saved to: {saved_path}")
             else:
                 self.log_via_queue("Live data log buffer was empty or failed to save.")
             self.live_dashboard.stop() # Ensure threads are joined

        if self.can_comm and self.can_comm.is_connected:
            self.log_via_queue("Initiating disconnect on close...");
            self.disconnect_can()
            self.root.after(750, self.root.destroy) # Allow time for disconnect
        else:
            self.root.destroy()

# --- Main execution block ---
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
    logging.info("Starting Car Diagnostics Application...")
    root = tk.Tk()
    app = CarDiagnosticsApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    try: root.mainloop()
    except KeyboardInterrupt: print("\nCaught KeyboardInterrupt, closing."); app.on_closing()
    finally: logging.info("Application closing.")