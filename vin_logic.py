# vin_logic.py

# Contains VIN matching and lookup logic

from typing import Optional, Dict, List, Any

# Import the data from vehicles.py
try:
    from vehicles import VEHICLES
except ImportError:
    print("Error: vehicles.py not found or VEHICLES data missing.")
    VEHICLES = [] # Provide an empty list to prevent crashes

def match_vin_wildcard(vin: str, wildcard_vin: str) -> bool:
    """Compares a VIN against a pattern with wildcards."""
    if len(vin) != len(wildcard_vin):
        return False
    for i in range(len(vin)):
        if wildcard_vin[i] == "*":
            continue
        if vin[i] != wildcard_vin[i]:
            return False
    return True

def lookup_vehicle_info(vin: str) -> Optional[Dict[str, Any]]:
    """Looks up vehicle information based on VIN from the VEHICLES data."""
    if not vin or not VEHICLES:
        return None

    vin = vin.upper() # Ensure consistent casing

    for vehicle_data in VEHICLES:
        pattern = vehicle_data.get("VIN")
        if pattern and match_vin_wildcard(vin, pattern.upper()):
            # Could add checks for VIN_From/VIN_To here for more accuracy if needed
            return vehicle_data

    # If no direct match, consider falling back to range check if needed. Not sure what will happen if V6 Emira is detected.
    print(f"Warning: VIN '{vin}' not found in vehicle database using wildcard match.")
    return None