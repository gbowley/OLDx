# main_gui.py
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog
import threading
import queue
import time
from datetime import datetime
import traceback
import logging
from typing import Optional, Dict, Any, Callable, List # Ensure Callable is imported
import re # For VIN validation
import os # For checking log file existence and icon path
import csv # For CSV export

# Import local modules
try:
    # Make sure ICanRawMessageProcessor is imported
    from can_communication import CanCommunication, ILiveDataProcessor, ICanRawMessageProcessor
    from vin_logic import lookup_vehicle_info
    from diagnostics import get_faults, clear_faults, get_performance_data, get_vin
    from live_dashboard import LiveDashboard, BROADCAST_LIVE_DATA_IDS, OBD_MODE_01_PIDS_TO_REQUEST, MODE_22_PIDS_TO_REQUEST
    from known_faults import FAULTS_CONFIRMED, FAULTS_PENDING
    from log_data import mode22_live_data
    from can_expert import CanExpert # ADDED: Import for the new tab
except ImportError as e:
     print(f"Fatal Error importing local modules: {e}"); exit(f"Import Error: {e}")
except Exception as e:
     print(f"Unexpected import error: {e}"); exit("Initialization Error")

# Basic VIN validation regex (17 alphanumeric chars, excluding I, O, Q)
VIN_REGEX = re.compile(r"^[A-HJ-NPR-Z0-9]{17}$", re.IGNORECASE)

# Global request update frequency options
UPDATE_FREQUENCIES = {
    "Hyperfast (75 ms)": 0.075,
    "Faster (100 ms)": 0.1,
    "Fast (125 ms)": 0.125,
    "Medium (250 ms)": 0.25,
    "Slow (500 ms)": 0.5,
}

# Define keys for the vehicle info section
VEHICLE_DETAIL_KEYS = [
    "Vehicle_Type", "Model_Year", "Market",
    "ECU_Program", "TCU_Program", "ABS_Program", "ABS_Module",
    "TPMS", "SRS", "IP", "Comment"
]

class CarDiagnosticsApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Open Lotus Diagnostics")
        self.root.minsize(900, 850) # Adjusted minsize slightly for potentially more content

        # --- Set Application Icon ---
        icon_path = 'oldx.ico' # Ensure this icon file is in the same directory or provide a full path
        if os.path.exists(icon_path):
            try:
                # Platform-specific icon setting
                if os.name == 'nt': # For Windows
                    self.root.iconbitmap(icon_path)
                # For other OS (like Linux with Tkinter's PhotoImage for icons)
                # else:
                #     img = tk.PhotoImage(file=icon_path)
                #     self.root.tk.call('wm', 'iconphoto', self.root._w, img)
            except Exception as e:
                print(f"Warning: Could not set application icon '{icon_path}': {e}")
        else:
            print(f"Warning: Application icon '{icon_path}' not found.")
        # --- End Icon Setting ---

        self.can_comm: Optional[CanCommunication] = None
        self.live_dashboard: Optional[LiveDashboard] = None
        self.can_expert_tab_instance: Optional[CanExpert] = None # ADDED: Instance for CAN Expert Tab

        self.gui_queue = queue.Queue()
        self.current_vin: Optional[str] = None
        self.vehicle_info: Optional[Dict[str, Any]] = None
        self.update_frequency_var = tk.DoubleVar(value=UPDATE_FREQUENCIES["Medium (250 ms)"]) # Default frequency
        self.all_dashboard_keys = set() # To store keys for dashboard items

        # --- Vehicle Info StringVars ---
        self.vin_display_var = tk.StringVar(value="---")
        self.model_display_var = tk.StringVar(value="---") # For the top frame
        self.vehicle_detail_vars: Dict[str, tk.StringVar] = {} # For the "Vehicle Details" tab
        for key in VEHICLE_DETAIL_KEYS:
            self.vehicle_detail_vars[key] = tk.StringVar(value="---")
        # --- End Vehicle Info StringVars ---

        # Styling
        style = ttk.Style()
        available_themes = style.theme_names()
        preferred_themes = ['vista', 'xpnative', 'win10', 'aqua', 'clam'] # Add more if desired
        theme_to_use = 'clam' # Default fallback
        for theme in preferred_themes:
             if theme in available_themes:
                 theme_to_use = theme
                 break
        try:
            style.theme_use(theme_to_use)
        except tk.TclError:
            print(f"Warning: Theme '{theme_to_use}' not found or failed to apply. Using default.")

        # --- Top Connection Frame ---
        conn_frame = ttk.LabelFrame(root, text="Connection", padding="10")
        conn_frame.pack(fill=tk.X, padx=10, pady=(10,5))
        conn_frame.columnconfigure(1, weight=1) # Interface combo
        conn_frame.columnconfigure(3, weight=1) # Channel entry
        conn_frame.columnconfigure(5, weight=0) # Bitrate combo (fixed width)
        conn_frame.columnconfigure(6, weight=0) # Connect button (fixed width)
        conn_frame.columnconfigure(7, weight=3) # Status label (expand)

        ttk.Label(conn_frame, text="Interface:").grid(row=0, column=0, padx=(0,5), pady=5, sticky=tk.W)
        self.iface_var = tk.StringVar(value="usb2can") # Default interface
        all_interfaces = ["usb2can", "socketcan", "pcan", "ixxat", "vector"] # Add more as supported by python-can
        self.iface_combo = ttk.Combobox(conn_frame, textvariable=self.iface_var, width=10, values=all_interfaces, state='readonly')
        self.iface_combo.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)

        ttk.Label(conn_frame, text="Channel:").grid(row=0, column=2, padx=(10,5), pady=5, sticky=tk.W)
        self.channel_entry = ttk.Entry(conn_frame, width=12)
        self.channel_entry.insert(0, "") # Placeholder for channel (e.g., "can0", "COM1", serial number)
        self.channel_entry.grid(row=0, column=3, padx=5, pady=5, sticky=tk.EW)

        ttk.Label(conn_frame, text="Bitrate:").grid(row=0, column=4, padx=(10,5), pady=5, sticky=tk.W)
        self.bitrate_var = tk.StringVar(value="500000") # Default bitrate
        bitrate_values = ["1000000", "500000", "250000", "125000"] # Common bitrates
        self.bitrate_combo = ttk.Combobox(conn_frame, textvariable=self.bitrate_var, width=8, values=bitrate_values) # Not readonly to allow custom
        self.bitrate_combo.grid(row=0, column=5, padx=5, pady=5, sticky=tk.W)

        self.connect_button = ttk.Button(conn_frame, text="Connect", command=self.toggle_connection, width=12)
        self.connect_button.grid(row=0, column=6, padx=(20, 5), pady=5, sticky=tk.E)

        self.status_label = ttk.Label(conn_frame, text="Status: Disconnected", foreground="red", anchor=tk.E)
        self.status_label.grid(row=0, column=7, padx=(5, 0), pady=5, sticky=tk.EW)

        # --- Vehicle Info Frame (Below Connection) ---
        vin_frame = ttk.LabelFrame(root, text="Vehicle Identification", padding="10")
        vin_frame.pack(fill=tk.X, padx=10, pady=5)
        vin_frame.columnconfigure(0, weight=0) # Get VIN button
        vin_frame.columnconfigure(2, weight=1) # VIN display entry
        vin_frame.columnconfigure(4, weight=2) # Model display label

        self.get_vin_button = ttk.Button(vin_frame, text="Get VIN / Identify", command=self.get_vin_action, state=tk.DISABLED)
        self.get_vin_button.grid(row=0, column=0, padx=(0, 10), pady=5, sticky=tk.W)

        ttk.Label(vin_frame, text="VIN:").grid(row=0, column=1, padx=(0, 5), pady=5, sticky=tk.E)
        vin_display_entry = ttk.Entry(vin_frame, textvariable=self.vin_display_var, state='readonly', width=25)
        vin_display_entry.grid(row=0, column=2, padx=(0, 10), pady=5, sticky=tk.EW)

        ttk.Label(vin_frame, text="Model:").grid(row=0, column=3, padx=(0, 5), pady=5, sticky=tk.E)
        model_display_label = ttk.Label(vin_frame, textvariable=self.model_display_var, anchor=tk.W, relief=tk.SUNKEN, borderwidth=1, background="white")
        model_display_label.grid(row=0, column=4, padx=(0, 0), pady=5, sticky=tk.EW)

        # --- Notebook for Tabs ---
        self.notebook = ttk.Notebook(root, padding="5")
        self.notebook.pack(expand=True, fill=tk.BOTH, padx=5, pady=(0,5))
        
        # Create frames for each tab
        self.faults_frame = ttk.Frame(self.notebook, padding="10")
        self.vehicle_details_frame = ttk.Frame(self.notebook, padding="10")
        self.dashboard_frame = ttk.Frame(self.notebook, padding="10")
        self.perf_frame = ttk.Frame(self.notebook, padding="10")
        self.can_expert_frame = ttk.Frame(self.notebook, padding="10") # ADDED: Frame for CAN Expert
        self.log_frame = ttk.Frame(self.notebook, padding="10")

        # Add tabs in desired order
        self.notebook.add(self.faults_frame, text=' Diagnostics & Faults ')
        self.create_faults_tab()
        
        self.notebook.add(self.vehicle_details_frame, text=' Vehicle Details ')
        self.create_vehicle_details_tab()
        
        self.notebook.add(self.dashboard_frame, text=' Live Dashboard ')
        self.create_dashboard_tab()
        
        self.notebook.add(self.perf_frame, text=' Performance Data ')
        self.create_performance_tab()

        # ADDED: Insert CAN Expert tab before Log tab
        self.notebook.add(self.can_expert_frame, text=' CAN (Expert) ')
        self.create_can_expert_tab() # Create its content

        self.notebook.add(self.log_frame, text=' Log ') # Add Log tab last
        self.create_log_tab()
        
        self.set_connected_state_buttons(False) # Initial button states
        self.root.after(100, self.process_gui_queue) # Start GUI queue processing

    # --- Tab Creation Methods ---
    def create_vehicle_details_tab(self):
        details_frame = self.vehicle_details_frame
        details_frame.columnconfigure(1, weight=1) # Column for first value
        details_frame.columnconfigure(3, weight=1) # Column for second value

        # Helper to add a row with two key-value pairs
        def add_info_row(row_index, key1, label1_text, key2, label2_text):
            ttk.Label(details_frame, text=label1_text + ":").grid(row=row_index, column=0, padx=5, pady=3, sticky=tk.E)
            ttk.Label(details_frame, textvariable=self.vehicle_detail_vars[key1], anchor=tk.W, relief=tk.SUNKEN, borderwidth=1, background="white", wraplength=200).grid(row=row_index, column=1, padx=5, pady=3, sticky=tk.EW)
            
            ttk.Label(details_frame, text=label2_text + ":").grid(row=row_index, column=2, padx=5, pady=3, sticky=tk.E)
            ttk.Label(details_frame, textvariable=self.vehicle_detail_vars[key2], anchor=tk.W, relief=tk.SUNKEN, borderwidth=1, background="white", wraplength=200).grid(row=row_index, column=3, padx=5, pady=3, sticky=tk.EW)

        # Helper to add a row with a single key-value pair spanning multiple columns
        def add_info_row_single(row_index, key, label_text, columnspan_val=3):
             ttk.Label(details_frame, text=label_text + ":").grid(row=row_index, column=0, padx=5, pady=3, sticky=tk.E)
             ttk.Label(details_frame, textvariable=self.vehicle_detail_vars[key], anchor=tk.W, relief=tk.SUNKEN, borderwidth=1, background="white", wraplength=400).grid(row=row_index, column=1, columnspan=columnspan_val, padx=5, pady=3, sticky=tk.EW)

        # Add rows for vehicle details using VEHICLE_DETAIL_KEYS
        add_info_row(0, "Vehicle_Type", "Type",       "Model_Year", "Year")
        add_info_row(1, "Market",        "Market",      "ECU_Program", "ECU Pgm")
        add_info_row(2, "TCU_Program",  "TCU Pgm",    "ABS_Program","ABS Pgm")
        add_info_row(3, "ABS_Module",  "ABS Mod",    "SRS", "SRS Mod") # Assuming "SRS" is a key in VEHICLE_DETAIL_KEYS
        add_info_row(4, "TPMS",           "TPMS",       "IP",       "IP Mod")   # Assuming "IP" is a key
        add_info_row_single(5, "Comment", "Comment", columnspan_val=3)

    def create_log_tab(self):
        log_controls_frame = ttk.Frame(self.log_frame)
        log_controls_frame.pack(fill=tk.X, pady=(0, 5)) # Padding only at bottom

        ttk.Label(log_controls_frame, text="Application Log:").pack(side=tk.LEFT, anchor=tk.W)
        ttk.Button(log_controls_frame, text="Clear Log", command=self.clear_log).pack(side=tk.RIGHT)
        
        text_display_frame = ttk.Frame(self.log_frame) # Frame to hold text and scrollbar
        text_display_frame.pack(expand=True, fill=tk.BOTH)

        self.log_text = scrolledtext.ScrolledText(text_display_frame, height=20, width=90, state=tk.DISABLED, wrap=tk.WORD)
        self.log_text.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)
        
        scrollbar = ttk.Scrollbar(text_display_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text['yscrollcommand'] = scrollbar.set
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    # ADDED: Method to create the CAN Expert Tab content
    def create_can_expert_tab(self):
        """Creates the UI and logic instance for the CAN (Expert) Tab."""
        # self.can_comm is initially None; it will be updated upon successful connection.
        # The CanExpertTab class itself will handle its internal UI creation.
        self.can_expert_tab_instance = CanExpert(
            parent_frame=self.can_expert_frame, # The ttk.Frame created for this tab
            can_comm=self.can_comm, # Pass the current (possibly None) CanCommunication instance
            gui_queue=self.gui_queue, # Pass the main GUI queue
            log_via_queue_callback=self.log_via_queue # Pass the logging callback
        )
        # The CanExpertTab's __init__ method calls its own _create_ui() to build its widgets.

    # --- Logging Methods ---
    def _update_log_widget(self, message: str): # Runs in GUI thread
        try:
            now = datetime.now().strftime("%H:%M:%S.%f")[:-3] # Timestamp with milliseconds
            self.log_text.config(state=tk.NORMAL)
            self.log_text.insert(tk.END, f"{now} - {message}\n")
            self.log_text.see(tk.END) # Scroll to the end
            self.log_text.config(state=tk.DISABLED)
        except tk.TclError: pass # Ignore errors if widget is destroyed during shutdown
        except Exception as e:
            print(f"Log GUI Error: {e}") # Fallback print

    def log_via_queue(self, message: str): # Can be called from any thread
        try:
            self.gui_queue.put(("log", str(message)))
        except Exception as e:
            # Fallback print if queue fails (e.g., during shutdown)
            print(f"LOG (queue error: {e}): {message}")

    def clear_log(self): # Runs in GUI thread
        try:
            self.log_text.config(state=tk.NORMAL)
            self.log_text.delete('1.0', tk.END)
            self.log_text.config(state=tk.DISABLED)
            self.log_via_queue("Log cleared by user.")
        except tk.TclError: pass
        except Exception as e:
            print(f"Error clearing log: {e}")

    # --- Connection Handling ---
    def update_status_label(self, text: str, color: str): # Runs in GUI thread
        try:
            self.status_label.config(text=f"Status: {text}", foreground=color)
        except tk.TclError: pass
        except Exception as e:
            print(f"Status Label Error: {e}")

    def toggle_connection(self): # Runs in GUI thread
        if self.can_comm and self.can_comm.is_connected:
            self.disconnect_can()
        else:
            self.connect_can()

    def connect_can(self): # Runs in GUI thread
        iface = self.iface_var.get()
        channel = self.channel_entry.get().strip()
        bitrate_str = self.bitrate_var.get()

        if not iface:
            messagebox.showerror("Input Error", "Please select an interface.", parent=self.root)
            return
        
        # Basic check for channel if usb2can on Windows (often needs serial number)
        import sys
        if sys.platform == "win32" and iface == "usb2can" and not channel:
            messagebox.showwarning("Channel May Be Required",
                                   "For 'usb2can' on Windows, the 'Channel' usually requires the device's serial number if multiple devices are present. Auto-detection might fail otherwise.",
                                   parent=self.root)
        
        if not bitrate_str:
            messagebox.showerror("Input Error", "Please select or enter a bitrate.", parent=self.root)
            return
        try:
            bitrate = int(bitrate_str)
            if bitrate <= 0: raise ValueError("Bitrate must be positive.")
        except ValueError:
            messagebox.showerror("Invalid Bitrate", f"The entered bitrate '{bitrate_str}' is not a valid number.", parent=self.root)
            return

        self.log_via_queue(f"Attempting to connect: Interface={iface}, Channel='{channel}', Bitrate={bitrate}...")
        self.update_status_label("Connecting...", "orange")
        self.connect_button.config(text="Connecting...", state=tk.DISABLED)
        # Disable input fields during connection attempt
        self.iface_combo.config(state=tk.DISABLED)
        self.channel_entry.config(state=tk.DISABLED)
        self.bitrate_combo.config(state=tk.DISABLED)
        
        # Start connection in a new thread to keep GUI responsive
        threading.Thread(target=self._connect_thread, args=(iface, channel, bitrate, self.gui_queue), daemon=True).start()

    def _connect_thread(self, iface: str, channel: str, bitrate: int, gui_queue_ref: queue.Queue):
        # Lambdas to simplify putting messages on the GUI queue from this thread
        log_func = lambda msg: gui_queue_ref.put(("log", msg))
        status_func = lambda data_dict: gui_queue_ref.put(("status", data_dict))
        reenable_ui_func = lambda conn_success_bool: gui_queue_ref.put(("reenable_connect_button", conn_success_bool))

        can_comm_instance = None
        live_dash_instance = None
        connection_successful = False
        
        # Temporary local instances to assign to self at the end if successful
        local_can_comm = None
        local_live_dashboard = None

        try:
            can_comm_instance = CanCommunication(channel=channel if channel else None, # Pass None if channel is empty
                                                 gui_queue=gui_queue_ref,
                                                 interface=iface,
                                                 bitrate=bitrate)
            if can_comm_instance.connect():
                connection_successful = True
                status_func({'text': "Connected", 'color': "green"})
                local_can_comm = can_comm_instance # Store valid instance

                # Initialize LiveDashboard if connection is successful
                try:
                     log_func("Connection established. Initializing live features...")
                     # time.sleep(0.5) # Small delay if needed for bus to stabilize, usually not necessary
                     current_freq = self.update_frequency_var.get() # Get current freq from GUI var
                     live_dash_instance = LiveDashboard(
                         local_can_comm, # Use the successfully connected instance
                         lambda data: gui_queue_ref.put(("live_data", data)), # Callback for live data
                         target_ids=None, # Let LiveDashboard use its defaults or be configured later
                         update_interval=current_freq
                     )
                     local_can_comm.register_live_dashboard_processor(live_dash_instance)
                     local_live_dashboard = live_dash_instance # Store valid instance
                     log_func("Live Dashboard processor registered.")
                except Exception as ld_e: 
                    log_func(f"Error initializing LiveDashboard: {ld_e}")
                    local_live_dashboard = None # Ensure it's None on error

                # ADDED: Update CanExpertTab with the new can_comm instance and register its processor
                if self.can_expert_tab_instance: # If the tab instance exists
                    self.can_expert_tab_instance.can_comm = local_can_comm # Provide it the comms layer
                    if local_can_comm: # If can_comm_instance is valid
                        # The CanExpertTab instance itself is the processor
                        local_can_comm.register_expert_raw_processor(self.can_expert_tab_instance)
                    log_func("CAN Expert Tab communication layer updated and processor registered.")

                # Assign to self attributes only if all initializations are fine
                self.can_comm = local_can_comm
                self.live_dashboard = local_live_dashboard
                
            else: # can_comm_instance.connect() returned False
                status_func({'text': "Connection Failed", 'color': "red"})
                # Ensure these are None if connection failed at CanCommunication level
                self.can_comm = None 
                self.live_dashboard = None
                if self.can_expert_tab_instance:
                    self.can_expert_tab_instance.can_comm = None
        except Exception as thread_e:
            log_func(f"Connection thread error: {thread_e}\n{traceback.format_exc()}")
            status_func({'text': "Connection Thread Error", 'color': "red"})
            self.can_comm = None
            self.live_dashboard = None
            if self.can_expert_tab_instance:
                self.can_expert_tab_instance.can_comm = None
        finally:
            # Signal GUI to re-enable connect button and update states
            reenable_ui_func(connection_successful)


    def disconnect_can(self): # Runs in GUI thread
        self.connect_button.config(text="Disconnecting...", state=tk.DISABLED)
        self.log_via_queue("Disconnect requested...")
        # Start disconnection in a new thread
        threading.Thread(target=self._disconnect_thread, daemon=True).start()

    def _disconnect_thread(self):
        # Stop Live Dashboard if running
        current_live_dashboard = self.live_dashboard
        if current_live_dashboard and current_live_dashboard.running:
            self.log_via_queue("Stopping Live Dashboard...")
            # Save log before stopping, if dashboard handles it internally or via a method call
            # current_live_dashboard.save_log_if_needed() # Example
            current_live_dashboard.stop()

        # ADDED: Handle CanExpertTab on disconnect
        if self.can_expert_tab_instance:
            self.log_via_queue("Stopping CAN Expert monitoring (if active) and saving log...")
            # This method should handle stopping monitoring and saving its CSV log
            self.can_expert_tab_instance.handle_stop_monitoring_on_disconnect()
            self.can_expert_tab_instance.can_comm = None # Clear its can_comm reference

        # Disconnect CAN communication
        current_can_comm = self.can_comm
        if current_can_comm:
             self.log_via_queue("Unregistering all processors...")
             if hasattr(current_can_comm, 'register_live_dashboard_processor'): 
                 current_can_comm.register_live_dashboard_processor(None) # Unregister live dashboard
             if hasattr(current_can_comm, 'register_expert_raw_processor'): # ADDED
                 current_can_comm.register_expert_raw_processor(None)      # ADDED: Unregister expert tab
             
             self.log_via_queue("Shutting down CAN connection...")
             current_can_comm.disconnect()
        else:
            self.log_via_queue("Disconnect: No active CAN connection found.")
        
        # Update GUI status and clear instances
        self.gui_queue.put(("status", {'text': "Disconnected", 'color': "red"}))
        self.gui_queue.put(("reenable_connect_button", False)) # False to indicate disconnected state
        self.gui_queue.put(("clear_instances", None)) # Action to nullify self.can_comm etc. in GUI thread


    def set_connected_state_buttons(self, connected: bool): # Runs in GUI thread
        action_button_state = tk.NORMAL if connected else tk.DISABLED
        input_field_state = tk.DISABLED if connected else tk.NORMAL # Connection inputs disabled when connected

        try:
            # Connection panel inputs
            self.iface_combo.config(state=input_field_state if input_field_state == tk.NORMAL else 'readonly')
            self.channel_entry.config(state=input_field_state)
            self.bitrate_combo.config(state=input_field_state if input_field_state == tk.NORMAL else 'readonly') # Bitrate can be custom

            # VIN button
            if hasattr(self, 'get_vin_button'):
                self.get_vin_button.config(state=action_button_state)

            # Faults tab buttons
            if hasattr(self, 'read_faults_button'):
                self.read_faults_button.config(state=action_button_state)
            if hasattr(self, 'clear_faults_button'):
                self.clear_faults_button.config(state=action_button_state)

            # Live Dashboard tab buttons
            if hasattr(self, 'start_dash_button'):
                # Start button enabled if connected AND dashboard is not already running
                can_start_dash = connected and (not self.live_dashboard or not self.live_dashboard.running)
                self.start_dash_button.config(state=tk.NORMAL if can_start_dash else tk.DISABLED)
            if hasattr(self, 'stop_dash_button'):
                # Stop button enabled if connected AND dashboard IS running
                can_stop_dash = connected and self.live_dashboard and self.live_dashboard.running
                self.stop_dash_button.config(state=tk.NORMAL if can_stop_dash else tk.DISABLED)
            if hasattr(self, 'freq_combo'): # Frequency combo enabled when disconnected or dash not running
                self.freq_combo.config(state='readonly' if (not connected or (self.live_dashboard and not self.live_dashboard.running)) else tk.DISABLED)


            # Performance Data tab button
            if hasattr(self, 'read_perf_button'):
                self.read_perf_button.config(state=action_button_state)

            # ADDED: Update CanExpertTab's UI state
            if self.can_expert_tab_instance:
                self.can_expert_tab_instance.update_connection_status(connected)
        
        except tk.TclError:
            pass # Ignore errors if widgets are not fully ready or destroyed
        except Exception as e:
            self.log_via_queue(f"Error updating button states: {e}") # Log other errors


    # --- VIN / Vehicle Info Handling ---
    def get_vin_action(self): # Runs in GUI thread
        if not self.can_comm or not self.can_comm.is_connected:
            messagebox.showerror("Error", "Not connected to CAN bus.", parent=self.root)
            return
        self.log_via_queue("Attempting to retrieve VIN and identify vehicle...")
        if hasattr(self, 'get_vin_button'): self.get_vin_button.config(state=tk.DISABLED)
        
        # Clear previous info
        self.vin_display_var.set("Reading...")
        self.model_display_var.set("---")
        for key in VEHICLE_DETAIL_KEYS:
            if key in self.vehicle_detail_vars: self.vehicle_detail_vars[key].set("---")
        self.vehicle_info = None # Clear internal vehicle info
        self.current_vin = None  # Clear internal VIN

        threading.Thread(target=self._get_vin_thread, daemon=True).start()

    def _get_vin_thread(self):
        vin_str = None
        vehicle_data = None
        request_manual_vin_entry = False # Flag to request manual input

        try:
            current_can_comm = self.can_comm # Local reference
            if current_can_comm and current_can_comm.is_connected:
                vin_str = get_vin(current_can_comm, self.log_via_queue) # get_vin from diagnostics.py
                if vin_str and "Error" not in vin_str and "Failed" not in vin_str: # Check if VIN was successfully read
                    self.log_via_queue(f"VIN successfully read from ECU: {vin_str}")
                    vehicle_data = lookup_vehicle_info(vin_str) # vin_logic.py
                    if vehicle_data:
                        self.log_via_queue(f"Vehicle identified: {vehicle_data.get('Model_Year', '')} {vehicle_data.get('Model', 'Unknown Model')}")
                    else:
                        self.log_via_queue(f"VIN {vin_str} read, but vehicle model is not found in the database.")
                else: # VIN read failed or returned an error string
                    self.log_via_queue(f"Failed to automatically read VIN from ECU (Result: {vin_str}). Requesting manual input.")
                    request_manual_vin_entry = True # Trigger manual VIN dialog
            else:
                self.log_via_queue("Error: CAN communication unavailable in VIN retrieval thread.")
        except Exception as e:
            self.log_via_queue(f"Exception during VIN retrieval task: {e}\n{traceback.format_exc()}")
            request_manual_vin_entry = True # Also request manual on unexpected error
        finally:
            if not request_manual_vin_entry: # If auto VIN read was successful
                self.gui_queue.put(("vehicle_info_update", {'vin': vin_str, 'vehicle': vehicle_data}))
            else: # If auto VIN failed or an error occurred
                self.gui_queue.put(("request_manual_vin", None)) # Signal GUI to ask for manual VIN

    def _handle_request_manual_vin(self, data=None): # Runs in GUI thread
        self.log_via_queue("Displaying manual VIN entry dialog...")
        manual_vin = simpledialog.askstring("Manual VIN Entry",
                                            "Automatic VIN reading failed or was inconclusive.\nPlease enter the 17-character VIN manually:",
                                            parent=self.root)
        vehicle_data = None
        vin_to_use_for_display = "Manual Entry Cancelled" # Default if dialog is cancelled

        if manual_vin: # If user entered something
            manual_vin = manual_vin.strip().upper()
            if VIN_REGEX.match(manual_vin): # Validate format
                self.log_via_queue(f"Manual VIN entered: {manual_vin}. Looking up vehicle information...")
                vin_to_use_for_display = manual_vin
                vehicle_data = lookup_vehicle_info(vin_to_use_for_display)
                if vehicle_data:
                    self.log_via_queue(f"Vehicle identified from manual VIN: {vehicle_data.get('Model_Year','')} {vehicle_data.get('Model','Unknown')}")
                else:
                    self.log_via_queue(f"Manual VIN {vin_to_use_for_display} is valid format, but vehicle model not found in database.")
            else: # Invalid format
                self.log_via_queue(f"Invalid VIN format entered manually: '{manual_vin}'.")
                messagebox.showerror("Invalid VIN", "The entered VIN is not valid. It must be 17 alphanumeric characters (letters A-Z, numbers 0-9, excluding I, O, Q).", parent=self.root)
                vin_to_use_for_display = "Manual Entry Invalid"
        else: # User cancelled the dialog
            self.log_via_queue("Manual VIN entry was cancelled by the user.")
        
        # Update GUI with the result of manual entry (or cancellation)
        self.gui_queue.put(("vehicle_info_update", {'vin': vin_to_use_for_display, 'vehicle': vehicle_data}))


    def _handle_vehicle_info_update(self, update_data: Dict[str, Any]): # Runs in GUI thread
        vin_str = update_data.get('vin')
        vehicle_data = update_data.get('vehicle')

        # Update internal state
        self.current_vin = vin_str if vin_str and "Manual Entry" not in vin_str and "Error" not in vin_str and "Failed" not in vin_str else None
        self.vehicle_info = vehicle_data

        # Update VIN display in the top frame
        self.vin_display_var.set(vin_str if vin_str else "---")

        if vehicle_data:
            # Update Model display in the top frame
            model_value = vehicle_data.get("Model", "---")
            model_year = vehicle_data.get("Model_Year", "")
            market = vehicle_data.get("Market", "")
            model_display_text = f"{model_year} {model_value}".strip()
            if market: model_display_text += f" ({market})"
            self.model_display_var.set(model_display_text if model_display_text else "---")

            # Update details in the "Vehicle Details" tab
            for key in VEHICLE_DETAIL_KEYS:
                value_to_set = vehicle_data.get(key, "---")
                if key in self.vehicle_detail_vars:
                     self.vehicle_detail_vars[key].set(str(value_to_set) if value_to_set else "---")
            self.log_via_queue("Vehicle information display updated.")
        else: # No vehicle_data found (e.g., VIN not in DB, or manual entry failed/cancelled)
            self.model_display_var.set("---" if not self.current_vin else "Vehicle Data Not Found")
            for key in VEHICLE_DETAIL_KEYS:
                if key in self.vehicle_detail_vars: self.vehicle_detail_vars[key].set("---")
            
            if self.current_vin: # VIN was read/entered but no match
                self.log_via_queue(f"VIN {self.current_vin} processed, but no matching vehicle data was found in the database.")
            elif "Error" in str(vin_str) or "Failed" in str(vin_str):
                 self.log_via_queue("VIN reading failed. Vehicle information cannot be displayed.")
            elif "Manual Entry Cancelled" in str(vin_str):
                 self.log_via_queue("Manual VIN entry cancelled. Vehicle information not updated.")
            elif "Manual Entry Invalid" in str(vin_str):
                 self.log_via_queue("Invalid manual VIN entered. Vehicle information not updated.")


        # Re-enable the "Get VIN" button
        self.action_reenable_vin_button()


    def action_reenable_vin_button(self, data=None): # Runs in GUI thread
         if hasattr(self, 'get_vin_button'):
             current_state = tk.NORMAL if self.can_comm and self.can_comm.is_connected else tk.DISABLED
             try:
                 self.get_vin_button.config(state=current_state)
             except tk.TclError: pass # Widget might not exist during shutdown

    # --- Faults Tab ---
    def create_faults_tab(self):
        button_frame = ttk.Frame(self.faults_frame)
        button_frame.pack(fill=tk.X, pady=5)
        self.read_faults_button = ttk.Button(button_frame, text="Read All Faults", command=self.read_faults_action, state=tk.DISABLED)
        self.read_faults_button.pack(side=tk.LEFT, padx=5)
        self.clear_faults_button = ttk.Button(button_frame, text="Clear All Faults", command=self.clear_faults_action, state=tk.DISABLED)
        self.clear_faults_button.pack(side=tk.LEFT, padx=5)

        ttk.Label(self.faults_frame, text="Detected Faults (DTCs):").pack(anchor=tk.W, pady=(10, 2))
        list_frame = ttk.Frame(self.faults_frame) # Frame for listbox and scrollbar
        list_frame.pack(expand=True, fill=tk.BOTH, pady=(0,5))
        self.faults_list = tk.Listbox(list_frame, height=15, width=90, selectmode=tk.EXTENDED)
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.faults_list.yview)
        self.faults_list.config(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.faults_list.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)

    def read_faults_action(self): # Runs in GUI thread
        if not self.can_comm or not self.can_comm.is_connected:
            messagebox.showerror("Error", "Not connected to CAN bus.", parent=self.root)
            return
        self.faults_list.delete(0, tk.END)
        self.faults_list.insert(tk.END, "Reading faults (using vehicle info if available)...")
        if hasattr(self, 'read_faults_button'): self.read_faults_button.config(state=tk.DISABLED)
        if hasattr(self, 'clear_faults_button'): self.clear_faults_button.config(state=tk.DISABLED)
        threading.Thread(target=self._read_faults_thread, daemon=True).start()

    def _read_faults_thread(self):
        fault_results = None
        try:
            current_can_comm = self.can_comm # Local reference
            if current_can_comm and current_can_comm.is_connected:
                # Pass vehicle_info to get_faults for module-specific logic
                fault_results = get_faults(current_can_comm, self.log_via_queue, self.vehicle_info)
            else:
                self.log_via_queue("Error: CAN communication unavailable in fault reading thread.")
        except Exception as e:
            self.log_via_queue(f"Exception during fault reading task: {e}\n{traceback.format_exc()}")
        finally:
            self.gui_queue.put(("faults_result", fault_results))
            self.gui_queue.put(("reenable_faults_buttons", None)) # Signal to re-enable buttons

    def display_faults(self, fault_data: Optional[Dict[str, List[str]]]): # Runs in GUI thread
        self.faults_list.delete(0, tk.END)
        line_count = 0
        has_actual_faults = False # Flag to check if any real faults were found

        if fault_data is None:
            self.faults_list.insert(tk.END, "Error during fault reading process.")
            self.faults_list.itemconfig(tk.END, {'fg': 'red'})
            return
        if not fault_data: # Empty dictionary
            self.faults_list.insert(tk.END, "No fault data received from modules, or no modules queried.")
            return

        for module_name in sorted(fault_data.keys()): # Sort for consistent display
            messages = fault_data[module_name]
            if messages: # If there are messages for this module
                self.faults_list.insert(tk.END, f"--- {module_name} ---")
                self.faults_list.itemconfig(line_count, fg='navy')
                line_count += 1
                for msg_index, msg_text in enumerate(messages):
                    self.faults_list.insert(tk.END, f"  {msg_text}")
                    # Color-coding logic
                    is_error_msg = "error" in msg_text.lower() or \
                                   "response" in msg_text.lower() or \
                                   "skipped" in msg_text.lower() or \
                                   "failure" in msg_text.lower() or \
                                   "nrc" in msg_text.lower()
                    is_no_faults_msg = "no faults found" in msg_text.lower() or \
                                       "no active faults" in msg_text.lower() or \
                                       "no dtcs reported" in msg_text.lower()
                    
                    if not is_error_msg and not is_no_faults_msg: # Assumed actual fault
                        self.faults_list.itemconfig(line_count, {'fg': 'red'})
                        has_actual_faults = True
                    elif is_no_faults_msg:
                        self.faults_list.itemconfig(line_count, {'fg': 'darkgreen'})
                    else: # Error, skip, or other info messages
                        self.faults_list.itemconfig(line_count, {'fg': 'black'}) # Default color
                    line_count += 1
                self.faults_list.insert(tk.END, "") # Add a blank line after each module's faults
                line_count += 1
        
        if not has_actual_faults and line_count > 0: # If iterated through modules but found no red faults
            self.faults_list.insert(tk.END, ">>> No active faults reported by responding/queried modules. <<<")
            self.faults_list.itemconfig(tk.END, {'fg': 'green'})
        elif line_count == 0: # If fault_data was not None but somehow resulted in no lines
             self.faults_list.insert(tk.END, "No data to display.")


    def clear_faults_action(self): # Runs in GUI thread
        if not self.can_comm or not self.can_comm.is_connected:
            messagebox.showerror("Error", "Not connected to CAN bus.", parent=self.root)
            return
        if not messagebox.askyesno("Confirm Clear Faults",
                                   "This will attempt to clear Diagnostic Trouble Codes from all supported modules.\n\n"
                                   "It is often necessary to cycle the ignition (OFF then ON) after clearing faults for them to be fully cleared or for the system to re-evaluate.\n\n"
                                   "Proceed with fault clearing?", parent=self.root):
            return
        self.log_via_queue("Starting fault clearing process...")
        if hasattr(self, 'read_faults_button'): self.read_faults_button.config(state=tk.DISABLED)
        if hasattr(self, 'clear_faults_button'): self.clear_faults_button.config(state=tk.DISABLED)
        threading.Thread(target=self._clear_faults_thread, daemon=True).start()

    def _clear_faults_thread(self):
        clear_results_data = None
        try:
             current_can_comm = self.can_comm # Local reference
             if current_can_comm and current_can_comm.is_connected:
                 # Pass vehicle_info for module-specific logic in clear_faults
                 clear_results_data = clear_faults(current_can_comm, self.log_via_queue, self.vehicle_info)
             else:
                 self.log_via_queue("Error: CAN communication unavailable in fault clearing thread.")
        except Exception as e:
            self.log_via_queue(f"Exception during fault clearing task: {e}\n{traceback.format_exc()}")
        finally:
            self.gui_queue.put(("clear_faults_result", clear_results_data))
            self.gui_queue.put(("reenable_faults_buttons", None)) # Signal to re-enable buttons
            self.log_via_queue("Fault clearing process finished. It's recommended to re-read faults after an ignition cycle.")


    def display_clear_results(self, clear_data: Optional[Dict[str, List[str]]]): # Runs in GUI thread
        self.log_via_queue("--- Fault Clearing Attempt Results ---")
        if clear_data is None:
            self.log_via_queue("  Error occurred during the fault clearing process.")
            return
        if not clear_data: # Empty dictionary
            self.log_via_queue("  No results returned from the fault clearing process (no modules attempted or no responses).")
            return
        
        for module_name in sorted(clear_data.keys()):
            self.log_via_queue(f"  Module: {module_name}")
            results_list = clear_data[module_name]
            if results_list:
                for result_str in results_list:
                    self.log_via_queue(f"    - {result_str}")
            else:
                self.log_via_queue(f"    - No specific result message logged for this module.")
        self.log_via_queue("------------------------------------")


    # --- Live Dashboard Tab ---
    def create_dashboard_tab(self):
        controls_frame = ttk.Frame(self.dashboard_frame)
        controls_frame.pack(fill=tk.X, pady=5)

        self.start_dash_button = ttk.Button(controls_frame, text="Start Dashboard", command=self.start_dashboard_action, state=tk.DISABLED)
        self.start_dash_button.pack(side=tk.LEFT, padx=5)
        self.stop_dash_button = ttk.Button(controls_frame, text="Stop Dashboard", command=self.stop_dashboard_action, state=tk.DISABLED)
        self.stop_dash_button.pack(side=tk.LEFT, padx=5)

        ttk.Label(controls_frame, text="Update Freq:").pack(side=tk.LEFT, padx=(20, 5))
        self.freq_combo = ttk.Combobox(controls_frame, values=list(UPDATE_FREQUENCIES.keys()), state='readonly', width=18) # Adjusted width
        self.freq_combo.set("Medium (250 ms)") # Default selection
        # self.update_frequency_var is already set in __init__
        self.freq_combo.bind("<<ComboboxSelected>>", self.on_frequency_change)
        self.freq_combo.pack(side=tk.LEFT, padx=5)

        # Frame for the grid of live data items
        data_items_frame = ttk.LabelFrame(self.dashboard_frame, text="Live Data Values", padding="10")
        data_items_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        num_display_columns = 6 # Number of Label+Value pairs per row
        label_width_chars = 20 # Approximate width for labels
        value_width_chars = 10 # Approximate width for values

        self.dashboard_vars: Dict[str, tk.StringVar] = {} # Store StringVars for live data
        current_row, current_col_pair = 0, 0 # Grid layout counters

        # Helper to add a dashboard item (label and value) to the grid
        def add_dashboard_item(key_name: str, display_label: str):
            nonlocal current_row, current_col_pair # Allow modification of outer scope vars
            self.all_dashboard_keys.add(key_name) # Track all keys added to the UI

            formatted_display_label = display_label + ":"
            # Label widget (e.g., "RPM:")
            label_widget = ttk.Label(data_items_frame, text=formatted_display_label, anchor=tk.E, width=label_width_chars)
            label_widget.grid(row=current_row, column=current_col_pair*2, sticky=tk.E, padx=(5,0), pady=3)
            
            # StringVar to hold the live value
            string_var = tk.StringVar(value="---") # Initial placeholder
            self.dashboard_vars[key_name] = string_var
            
            # Value display widget (readonly, styled like an entry)
            value_widget = ttk.Label(data_items_frame, textvariable=string_var, anchor=tk.W, width=value_width_chars,
                                     relief=tk.SUNKEN, borderwidth=1, padding=(3,1))
            value_widget.grid(row=current_row, column=current_col_pair*2 + 1, sticky=tk.EW, padx=(0,10), pady=3)
            
            # Configure column weight for the value part to expand
            data_items_frame.columnconfigure(current_col_pair*2 + 1, weight=1)
            
            current_col_pair += 1
            if current_col_pair >= num_display_columns: # Move to next row
                current_col_pair = 0
                current_row += 1

        # --- Define Dashboard Items ---
        # Basic ECU/Cluster Data
        add_dashboard_item('rpm', 'RPM')
        add_dashboard_item('apps', 'Pedal Pos (%)')
        add_dashboard_item('throttlePos', 'Throttle Pos (%)')
        add_dashboard_item('maf', 'MAF (g/s)')
        add_dashboard_item('timingAdv', 'Timing Adv (deg)')
        add_dashboard_item('gearAuto', 'Gear (Auto)')

        # Temperatures
        add_dashboard_item('coolant', 'Coolant Temp (°C)')
        add_dashboard_item('iat', 'Intake Air Temp (°C)')
        add_dashboard_item('aat', 'Ambient Air Temp (°C)')
        add_dashboard_item('fuelLevel', 'Fuel Level (%)') # Moved here

        # Fueling - Bank 1
        add_dashboard_item('lambdaB1', 'Lambda Bank 1')
        add_dashboard_item('stftB1', 'STFT Bank 1 (%)')
        add_dashboard_item('ltftB1', 'LTFT Bank 1 (%)')
        add_dashboard_item('fuelLearnDTB1', 'Fuel Learn DT B1 (µs)')
        add_dashboard_item('fuelLearnZ2B1', 'Fuel Learn Z2 B1 (%)')
        add_dashboard_item('fuelLearnZ3B1', 'Fuel Learn Z3 B1 (%)')

        # Fueling - Bank 2 (if applicable)
        add_dashboard_item('lambdaB2', 'Lambda Bank 2')
        add_dashboard_item('stftB2', 'STFT Bank 2 (%)')
        add_dashboard_item('ltftB2', 'LTFT Bank 2 (%)')
        add_dashboard_item('fuelLearnDTB2', 'Fuel Learn DT B2 (µs)')
        add_dashboard_item('fuelLearnZ2B2', 'Fuel Learn Z2 B2 (%)')
        add_dashboard_item('fuelLearnZ3B2', 'Fuel Learn Z3 B2 (%)')

        # Knock Retard per Cylinder
        for i in range(1, 7): # Cylinders 1-6
            add_dashboard_item(f'knockCyl{i}', f'Knock Cyl {i} (deg)')

        # Switches / Status Indicators
        add_dashboard_item('brakeSwitch', 'Brake Switch')
        add_dashboard_item('sportSwitch', 'Sport Switch')
        add_dashboard_item('mil', 'MIL Lamp (CEL)')
        add_dashboard_item('lowOilPressure', 'Low Oil Pressure Warn')
        add_dashboard_item('tpmsFault', 'TPMS Fault Warn')

        # ESP/ABS/ASR Status
        add_dashboard_item('espIntervention', 'ESP Intervention')
        add_dashboard_item('espAbsIntervention', 'ESP/ABS Intervention')
        add_dashboard_item('espSystemState', 'ESP System State') # e.g., On, Off, Fail
        add_dashboard_item('espAbsErrorState', 'ESP/ABS Error State')
        add_dashboard_item('espAsrErrorState', 'ASR Error State')
        add_dashboard_item('espErrorState', 'ESP Main Error State')

        # Cluster Misc
        add_dashboard_item('shiftLight1', 'Shift Light 1')
        add_dashboard_item('shiftLight2', 'Shift Light 2')
        add_dashboard_item('shiftLight3', 'Shift Light 3')
        add_dashboard_item('time', 'ECU Time/Date') # From cluster or ECU
        add_dashboard_item('textMessage', 'Cluster Text Msg') # For info messages on dash

    def on_frequency_change(self, event=None): # event is passed by ComboboxSelected
        selected_text = self.freq_combo.get()
        new_freq_value = UPDATE_FREQUENCIES.get(selected_text, 0.25) # Default to Medium if key not found
        self.update_frequency_var.set(new_freq_value)
        self.log_via_queue(f"Live Dashboard request interval set to {new_freq_value} seconds.")
        if self.live_dashboard and self.live_dashboard.running:
            self.live_dashboard.set_update_interval(new_freq_value)

    def start_dashboard_action(self): # Runs in GUI thread
        if not self.can_comm or not self.can_comm.is_connected:
            messagebox.showerror("Error", "CAN bus not connected. Please connect first.", parent=self.root)
            return

        if not self.live_dashboard: # First time starting or after a full disconnect
            try:
                current_freq = self.update_frequency_var.get()
                self.live_dashboard = LiveDashboard(
                    self.can_comm,
                    lambda data: self.gui_queue.put(("live_data", data)), # Callback for GUI updates
                    target_ids=None, # Let LiveDashboard decide which broadcast IDs to listen to initially
                    update_interval=current_freq
                )
                self.can_comm.register_live_dashboard_processor(self.live_dashboard)
                self.log_via_queue(f"Live Dashboard initialized (Request Interval: {current_freq}s).")
            except Exception as ld_init_e:
                messagebox.showerror("Initialization Error", f"Failed to initialize Live Dashboard: {ld_init_e}", parent=self.root)
                self.log_via_queue(f"Live Dashboard initialization failed: {ld_init_e}")
                self.live_dashboard = None # Ensure it's None on failure
                return # Don't proceed to start
        else: # Dashboard instance exists, likely restarting
            self.live_dashboard.clear_log_buffer() # Clear any previous log data
            self.log_via_queue("Cleared previous live data log buffer before starting.")
            # Ensure the update interval is current
            self.live_dashboard.set_update_interval(self.update_frequency_var.get())


        try:
             if self.live_dashboard and self.live_dashboard.start(): # Attempt to start
                 self.log_via_queue("Live dashboard started successfully.")
                 # Update button states
                 self.start_dash_button.config(state=tk.DISABLED)
                 self.stop_dash_button.config(state=tk.NORMAL)
                 self.freq_combo.config(state=tk.DISABLED) # Disable freq change while running
                 # Initialize display values to "..."
                 for key_name in self.all_dashboard_keys: # Iterate over keys known to the UI
                     if key_name in self.dashboard_vars:
                         self.dashboard_vars[key_name].set("...")
                     # else: # Should not happen if all_dashboard_keys is populated correctly
                     #     print(f"Warning: Key '{key_name}' from all_dashboard_keys not found in dashboard_vars during start.")
             else: # Start command failed (e.g., already running, or internal start error)
                 self.log_via_queue("Live dashboard start command failed (possibly already running or an internal issue).")
                 # Optionally, refresh button states based on current dashboard running state
                 self.set_connected_state_buttons(True) # Refresh all button states
        except Exception as e_start:
             messagebox.showerror("Start Error", f"An error occurred while starting the live dashboard: {e_start}", parent=self.root)
             self.log_via_queue(f"Error starting live dashboard: {e_start}")


    def stop_dashboard_action(self): # Runs in GUI thread
        if self.live_dashboard:
            # Save log data to CSV before stopping
            saved_log_path = self.live_dashboard.save_log_to_csv()
            if saved_log_path:
                self.log_via_queue(f"Live data log saved to: {saved_log_path}")
            else:
                 self.log_via_queue("Live data log buffer was empty or failed to save upon stopping.")

            self.live_dashboard.stop() # Stop the dashboard processing
            self.log_via_queue("Live dashboard stopped by user.")
            
            # Update button states
            self.start_dash_button.config(state=tk.NORMAL if self.can_comm and self.can_comm.is_connected else tk.DISABLED)
            self.stop_dash_button.config(state=tk.DISABLED)
            self.freq_combo.config(state='readonly') # Re-enable frequency combo

            # Reset displayed values to "---"
            for key_name in self.dashboard_vars:
                self.dashboard_vars[key_name].set("---")
        else:
            self.log_via_queue("Stop dashboard action: No live dashboard instance was active.")
            # Ensure buttons are in a consistent state if dashboard was somehow not instanced but stop was clickable
            self.start_dash_button.config(state=tk.NORMAL if self.can_comm and self.can_comm.is_connected else tk.DISABLED)
            self.stop_dash_button.config(state=tk.DISABLED)
            self.freq_combo.config(state='readonly')


    def update_dashboard_values(self, data_update: Dict[str, Any]): # Runs in GUI thread
        if not isinstance(data_update, dict):
            self.log_via_queue(f"Warning: Invalid data type received for dashboard update: {type(data_update)}")
            return
        
        for key, raw_value in data_update.items():
            if key in self.dashboard_vars:
                target_var = self.dashboard_vars[key]
                formatted_display_value = "" # Default to empty string

                if raw_value is None or raw_value == "N/A" or raw_value == "...": # Handle placeholders explicitly
                    formatted_display_value = str(raw_value) if raw_value is not None else "---"
                elif isinstance(raw_value, float):
                    # Apply specific formatting based on key type
                    if key in ['rpm', 'coolant', 'iat', 'aat', 'timingAdv'] or 'Knock' in key:
                         formatted_display_value = f"{raw_value:.1f}" # 1 decimal place
                    elif 'Lambda' in key:
                         formatted_display_value = f"{raw_value:.3f}" # 3 decimal places for precision
                    elif 'FT' in key or 'Learn' in key or 'Pos' in key or 'Level' in key or 'maf' in key: # Trims, learns, positions, MAF
                         formatted_display_value = f"{raw_value:.2f}" # 2 decimal places
                    else: # Generic float
                         formatted_display_value = f"{raw_value:.2f}"
                elif isinstance(raw_value, int):
                    formatted_display_value = str(raw_value)
                elif isinstance(raw_value, bool):
                    formatted_display_value = "ON" if raw_value else "OFF"
                else: # Strings or other types
                    formatted_display_value = str(raw_value)
                
                try: # Update the Tkinter StringVar
                     if target_var.get() != formatted_display_value: # Only update if value changed
                         target_var.set(formatted_display_value)
                except tk.TclError: pass # Widget might be destroyed
                except Exception as e_set:
                    self.log_via_queue(f"Error setting dashboard variable for key '{key}': {e_set}")


    # --- Performance Data Tab ---
    def create_performance_tab(self):
        button_frame = ttk.Frame(self.perf_frame)
        button_frame.pack(fill=tk.X, pady=5)
        self.read_perf_button = ttk.Button(button_frame, text="Read ECU Performance Log Data", command=self.read_performance_action, state=tk.DISABLED)
        self.read_perf_button.pack(side=tk.LEFT, padx=5)

        ttk.Label(self.perf_frame, text="ECU Stored Performance Log Data:").pack(anchor=tk.W, pady=(10, 2))
        
        text_display_frame = ttk.Frame(self.perf_frame) # Frame for text and scrollbar
        text_display_frame.pack(expand=True, fill=tk.BOTH, pady=(0,5))
        self.perf_text = scrolledtext.ScrolledText(text_display_frame, height=20, width=90, state=tk.DISABLED, wrap=tk.WORD)
        scrollbar = ttk.Scrollbar(text_display_frame, orient=tk.VERTICAL, command=self.perf_text.yview)
        self.perf_text['yscrollcommand'] = scrollbar.set
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.perf_text.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)

    def read_performance_action(self): # Runs in GUI thread
        if not self.can_comm or not self.can_comm.is_connected:
            messagebox.showerror("Error", "Not connected to CAN bus.", parent=self.root)
            return
        
        # Clear previous data and show "Reading..."
        self.perf_text.config(state=tk.NORMAL)
        self.perf_text.delete('1.0', tk.END)
        self.perf_text.insert('1.0', "Attempting to read ECU performance log data...\nThis may take a few moments.\n\n")
        self.perf_text.config(state=tk.DISABLED)
        
        if hasattr(self, 'read_perf_button'): self.read_perf_button.config(state=tk.DISABLED)
        threading.Thread(target=self._read_performance_thread, daemon=True).start()

    def _read_performance_thread(self):
        performance_data_results = None
        try:
             current_can_comm = self.can_comm # Local reference
             if current_can_comm and current_can_comm.is_connected:
                 performance_data_results = get_performance_data(current_can_comm, self.log_via_queue) # From diagnostics.py
             else:
                 self.log_via_queue("Error: CAN communication unavailable in performance data reading thread.")
        except Exception as e:
            self.log_via_queue(f"Exception during performance data reading task: {e}\n{traceback.format_exc()}")
        finally:
            self.gui_queue.put(("perf_data_result", performance_data_results))
            self.gui_queue.put(("reenable_perf_button", None)) # Signal to re-enable button

    def display_performance_data(self, perf_data: Optional[Dict[str, str]]): # Runs in GUI thread
        self.perf_text.config(state=tk.NORMAL)
        self.perf_text.delete('1.0', tk.END) # Clear "Reading..." message

        if perf_data is None:
            self.perf_text.insert('1.0', "Error: Failed to retrieve performance data from ECU.")
            self.perf_text.tag_add("error_msg", "1.0", tk.END)
            self.perf_text.tag_config("error_msg", foreground="red")
        elif not perf_data: # Empty dictionary
            self.perf_text.insert('1.0', "No performance data was returned by the ECU, or the feature is not supported.")
        else:
            # Determine max label length for alignment (excluding headers)
            max_label_len = 0
            non_header_keys = [k for k in perf_data.keys() if not k.startswith("---")]
            if non_header_keys:
                try: max_label_len = max(len(k) for k in non_header_keys) + 2 # Add padding
                except ValueError: max_label_len = 30 # Default if no non-header keys
            else: max_label_len = 30

            # Define tags for styling
            self.perf_text.tag_configure("header_style", foreground="navy")
            self.perf_text.tag_configure("error_value_style", foreground="orange")

            for label, value_str in perf_data.items():
                 line_start_index = self.perf_text.index(tk.END + "-1c") # Get start of current line being inserted
                 
                 if label.startswith("---"): # It's a header/separator
                     self.perf_text.insert(tk.END, f"\n{label}\n") # Add extra newlines around headers
                     # Apply header style to the inserted header line
                     self.perf_text.tag_add("header_style", line_start_index + "+1l", self.perf_text.index(tk.END + "-1l"))
                 else: # It's a data item
                      # Format with fixed-width label part for alignment
                      formatted_line = f"{label:<{max_label_len}}: {value_str}\n"
                      self.perf_text.insert(tk.END, formatted_line)
                      
                      # If the value indicates an error or missing data, style it
                      if isinstance(value_str, str) and \
                         ("Error" in value_str or "Timeout" in value_str or "N/A" in value_str or "Missing" in value_str or "Failed" in value_str):
                           # Calculate start of the value part to apply style only to value
                           value_display_start_index = f"{line_start_index}+{max_label_len + 2}c" # Index after label and colon-space
                           self.perf_text.tag_add("error_value_style", value_display_start_index, self.perf_text.index(tk.END + "-1l"))
        
        self.perf_text.config(state=tk.DISABLED) # Make text area read-only again


    # --- Re-enable Buttons Actions (called from GUI queue) ---
    def action_reenable_connect_button(self, connection_successful: bool): # Runs in GUI thread
        try:
            self.connect_button.config(state=tk.NORMAL) # Always re-enable the button itself
            if connection_successful:
                self.connect_button.config(text="Disconnect")
            else: # Connection failed or was a disconnect operation
                self.connect_button.config(text="Connect")
            self.set_connected_state_buttons(connection_successful) # Update all other buttons based on new state
        except tk.TclError: pass

    def action_clear_instances(self, data=None): # Runs in GUI thread
        self.can_comm = None
        self.live_dashboard = None
        # ADDED: Clear can_comm from expert tab instance as well
        if self.can_expert_tab_instance:
            self.can_expert_tab_instance.can_comm = None
        self.log_via_queue("Internal communication instances cleared after disconnect.")

    def action_reenable_faults_buttons(self, data=None): # Runs in GUI thread
        # Re-evaluates button states based on current connection status
        self.set_connected_state_buttons(self.can_comm is not None and self.can_comm.is_connected)

    def action_reenable_perf_button(self, data=None): # Runs in GUI thread
        self.set_connected_state_buttons(self.can_comm is not None and self.can_comm.is_connected)


    # --- GUI Queue Processing ---
    def _handle_status_update(self, data: Dict[str, str]): # Handler for "status" action
         if isinstance(data, dict) and 'text' in data and 'color' in data:
             self.update_status_label(data['text'], data['color'])
         else: # Should not happen if data is put correctly
             self.log_via_queue(f"Warning: Invalid status data received in queue: {data}")

    # ADDED: Handler for CAN Expert Tab display updates
    def _handle_can_expert_display_update(self, text_line: str):
        """Appends a line to the CAN Expert tab's display area."""
        if self.can_expert_tab_instance and self.can_expert_tab_instance.message_display:
            try:
                disp = self.can_expert_tab_instance.message_display
                disp.config(state=tk.NORMAL)
                disp.insert(tk.END, text_line + "\n") # Add newline for each message
                disp.see(tk.END) # Scroll to the latest message
                disp.config(state=tk.DISABLED)
            except tk.TclError:
                pass # Widget might not be available during shutdown or tab switch
            except Exception as e:
                self.log_via_queue(f"Error updating CAN Expert display: {e}")

    # Define ACTION_MAP as a class attribute or instance attribute in __init__
    # For simplicity as a class attribute here, ensure methods are defined before this.
    # If methods need `self` implicitly, they should be instance methods.
    ACTION_MAP: Dict[str, Callable[[Any, Any], None]] = { # Type hint for clarity
        "log": _update_log_widget, # Note: if these are instance methods, self is passed implicitly
        "status": _handle_status_update,
        "faults_result": display_faults,
        "clear_faults_result": display_clear_results,
        "perf_data_result": display_performance_data,
        "live_data": update_dashboard_values,
        "reenable_connect_button": action_reenable_connect_button,
        "reenable_faults_buttons": action_reenable_faults_buttons,
        "reenable_perf_button": action_reenable_perf_button,
        "clear_instances": action_clear_instances,
        "vehicle_info_update": _handle_vehicle_info_update,
        "request_manual_vin": _handle_request_manual_vin,
        "can_expert_display_update": _handle_can_expert_display_update, # ADDED for CAN Expert
    }

    def process_gui_queue(self): # Runs in GUI thread
        try:
            while True: # Process all messages currently in the queue
                action, data = self.gui_queue.get_nowait() # Non-blocking get
                
                handler = self.ACTION_MAP.get(action)
                if handler:
                    try:
                        # Call the handler. Since ACTION_MAP stores method references bound to `self` (implicitly for instance methods),
                        # or static/module level functions, `self` is handled correctly.
                        # We pass `self` explicitly here if ACTION_MAP stores unbound methods or functions needing the instance.
                        # However, if ACTION_MAP is defined as above with instance methods, `self` is implicit.
                        # Let's assume they are instance methods:
                        handler(self, data) # Pass `self` and then `data`
                    except Exception as e_handler:
                        error_msg = f"GUI Error processing action '{action}': {e_handler}"
                        print(error_msg) # Fallback print
                        self.log_via_queue(error_msg) # Log to GUI log as well
                        traceback.print_exc() # For development debugging
                else:
                    print(f"Warning: No GUI handler defined for action '{action}'")
        except queue.Empty:
            pass # No messages in queue, normal
        except Exception as e_queue: # Catch any other unexpected errors in queue processing
            print(f"Critical error in process_gui_queue: {e_queue}")
            traceback.print_exc()
        finally:
            # Reschedule this method to run again after a short delay
            if hasattr(self.root, 'winfo_exists') and self.root.winfo_exists(): # Check if root window still exists
                self.root.after(100, self.process_gui_queue) # 100ms interval

    def on_closing(self): # Handle window close event
        self.log_via_queue("Window closing signal received...")
        
        # Stop Live Dashboard and save log if running
        if self.live_dashboard and self.live_dashboard.running:
             self.log_via_queue("Stopping Live Dashboard and saving its log on application close...")
             saved_path = self.live_dashboard.save_log_to_csv() # Attempt to save CSV
             if saved_path:
                 self.log_via_queue(f"Live Dashboard data log saved to: {saved_path}")
             else:
                 self.log_via_queue("Live Dashboard log buffer was empty or failed to save.")
             self.live_dashboard.stop() # Ensure dashboard thread is joined

        # Stop CAN Expert Tab monitoring and save its log if active
        if self.can_expert_tab_instance and self.can_expert_tab_instance.is_monitoring:
            self.log_via_queue("Stopping CAN Expert monitoring and saving its log on application close...")
            self.can_expert_tab_instance.handle_stop_monitoring_on_disconnect() # This should save CSV

        # Disconnect CAN if connected
        if self.can_comm and self.can_comm.is_connected:
            self.log_via_queue("Initiating CAN disconnect on application close...")
            # self.disconnect_can() # This starts a thread, might not finish before destroy
            # Direct call to _disconnect_thread parts might be too complex here.
            # A simple approach:
            if hasattr(self.can_comm, 'disconnect'): self.can_comm.disconnect() # Try direct disconnect
            self.log_via_queue("CAN disconnect process initiated.")
            # Give a moment for threads to attempt cleanup, though not guaranteed
            # self.root.after(750, self.root.destroy) # Delay destroy if disconnect is threaded
            self.root.destroy() # Destroy immediately if disconnect is blocking or for simplicity
        else:
            self.root.destroy() # No CAN connection, just destroy window

# --- Main execution block ---
if __name__ == "__main__":
    # Configure basic logging for console output (optional, GUI log is primary for user)
    logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
    logging.info("Starting Car Diagnostics Application...")

    root = tk.Tk()
    app = CarDiagnosticsApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing) # Handle window close button
    
    try:
        root.mainloop()
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt detected. Closing application...")
        app.on_closing() # Graceful shutdown on Ctrl+C
    finally:
        logging.info("Application has been closed.")
