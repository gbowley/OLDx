# performance_data.py

# Contains the dictionary defining performance data items to be captured.

# --- Performance Data Logic ---
PERFORMANCE_DATA_ITEMS = {
    # --- Time@TPS ---
    "Time@TPS 0-1.5%": ("0301", 0, 0.1, 1, True),
    "Time@TPS 1.5-15%": ("0302", 0, 0.1, 1, True),
    "Time@TPS 15-25%": ("0303", 0, 0.1, 1, True),
    "Time@TPS 25-35%": ("0304", 0, 0.1, 1, True),
    "Time@TPS 35-50%": ("0305", 0, 0.1, 1, True),
    "Time@TPS 50-65%": ("0306", 0, 0.1, 1, True),
    "Time@TPS 65-80%": ("0307", 0, 0.1, 1, True),
    "Time@TPS 80-100%": ("0308", 0, 0.1, 1, True),
    # --- Time@RPM ---
    "Time@RPM 500-1500": ("0309", 0, 0.1, 1, True),
    "Time@RPM 1500-2500": ("030A", 0, 0.1, 1, True),
    "Time@RPM 2500-3500": ("030B", 0, 0.1, 1, True),
    "Time@RPM 3500-4500": ("030C", 0, 0.1, 1, True),
    "Time@RPM 4500-5500": ("030D", 0, 0.1, 1, True),
    "Time@RPM 5500-6500": ("030E", 0, 0.1, 1, True),
    "Time@RPM 6500-7000": ("030F", 0, 0.1, 1, True),
    "Time@RPM 7000+": ("0310", 0, 0.1, 1, True),
    # --- Time@Speed ---
    "Time@Speed 0-30": ("0311", 0, 0.1, 1, True),
    "Time@Speed 30-60": ("0312", 0, 0.1, 1, True),
    "Time@Speed 60-90": ("0313", 0, 0.1, 1, True),
    "Time@Speed 90-120": ("0314", 0, 0.1, 1, True),
    "Time@Speed 120-150": ("0315", 0, 0.1, 1, True),
    "Time@Speed 150-180": ("0316", 0, 0.1, 1, True),
    "Time@Speed 180-210": ("0317", 0, 0.1, 1, True),
    "Time@Speed 210+": ("0318", 0, 0.1, 1, True),
    # --- Time@Coolant Temp ---
    "Time@Coolant 105-110C": ("031A", 0, 0.1, 1, True),
    "Time@Coolant 110-115C": ("031B", 0, 0.1, 1, True),
    "Time@Coolant 115-119C": ("031C", 0, 0.1, 1, True),
    "Time@Coolant 119C+": ("031D", 0, 0.1, 1, True),
    # --- Significant Events ---
    "Event 1 RPM": ("031E", 0, 1, 0, False),
    "Event 2 RPM": ("031F", 0, 1, 0, False),
    "Event 3 RPM": ("0321", 0, 1, 0, False),
    "Event 4 RPM": ("0322", 0, 1, 0, False),
    "Event 5 RPM": ("0323", 0, 1, 0, False),
    "Event 1 Coolant (C)": ("0324", -60, 0.6, 1, False), # Assuming C based on other temp scales
    "Event 1 Time": ("0325", 0, 0.1, 1, True),
    "Event 2 Coolant (C)": ("0326", -60, 0.6, 1, False),
    "Event 2 Time": ("0327", 0, 0.1, 1, True),
    "Event 3 Coolant (C)": ("0328", -60, 0.6, 1, False),
    "Event 3 Time": ("0329", 0, 0.1, 1, True),
    "Event 4 Coolant (C)": ("032A", -60, 0.6, 1, False),
    "Event 4 Time": ("032B", 0, 0.1, 1, True),
    "Event 5 Coolant (C)": ("032C", -60, 0.6, 1, False),
    "Event 5 Time": ("032E", 0, 0.1, 1, True),
    # --- Max Speed Events (km/h) --- 16-bit data assumed (divided by 65536)
    "Max Speed 1 (km/h)": ("032F", 0, 1 / 65536, 0, False), 
    "Max Speed 2 (km/h)": ("0330", 0, 1 / 65536, 0, False),
    "Max Speed 3 (km/h)": ("0331", 0, 1 / 65536, 0, False),
    "Max Speed 4 (km/h)": ("0332", 0, 1 / 65536, 0, False),
    "Max Speed 5 (km/h)": ("0333", 0, 1 / 65536, 0, False),
    # --- Standing Starts ---
    "Fastest 0-100 (s)": ("0334", 0, 0.1, 1, False), # Note: 0xFF000000 raw means 'Never'
    "Fastest 0-160 (s)": ("0335", 0, 0.1, 1, False), # Note: 0xFF000000 raw means 'Never'
    "Last 0-100 (s)": ("0336", 0, 0.1, 1, False),   # Note: 0xFF000000 raw means 'Never'
    "Last 0-160 (s)": ("0337", 0, 0.1, 1, False),   # Note: 0xFF000000 raw means 'Never'
    "Total Engine Runtime": ("0338", 0, 0.1, 1, True),
    "Num Standing Starts": ("0339", 0, 1, 0, False),
    # --- Time@Lateral G ---
    "Time@G 0.0-0.6": ("033B", 0, 0.1, 1, True),
    "Time@G 0.6-0.8": ("033C", 0, 0.1, 1, True),
    "Time@G 0.8-1.0": ("033D", 0, 0.1, 1, True),
    "Time@G 1.0-1.2": ("033E", 0, 0.1, 1, True),
    "Time@G 1.2-1.4": ("033F", 0, 0.1, 1, True),
    # --- Low Oil Pressure Events ---
    "Low Oil P Evts Count": ("0361", 0, 1/16777216, 0, False),
    "Low Oil P 1 Duration(s)": ("0342", 0, 0.000000006 * 2**24, 1, False),
    "Low Oil P 1 Speed": ("0343", 0, 1, 0, False),
    "Low Oil P 1 RPM": ("0344", 0, 1 / 65536, 0, False),
    "Low Oil P 1 PeakG": ("0345", 0, 1, 1, False),
    "Low Oil P 1 Time": ("0346", 0, 0.1, 1, True),
    "Low Oil P 2 Duration(s)": ("0347", 0, 0.000000006 * 2**24, 1, False),
    "Low Oil P 2 Speed": ("0348", 0, 1, 0, False),
    "Low Oil P 2 RPM": ("0349", 0, 1 / 65536, 0, False),
    "Low Oil P 2 PeakG": ("034A", 0, 1, 1, False),
    "Low Oil P 2 Time": ("034B", 0, 0.1, 1, True),
    "Low Oil P 3 Duration(s)": ("034C", 0, 0.000000006 * 2**24, 1, False),
    "Low Oil P 3 Speed": ("034D", 0, 1, 0, False),
    "Low Oil P 3 RPM": ("034E", 0, 1 / 65536, 0, False),
    "Low Oil P 3 PeakG": ("034F", 0, 1, 1, False),
    "Low Oil P 3 Time": ("0350", 0, 0.1, 1, True),
    # --- High Lateral G Events ---
    "HighG 1 Duration(s)": ("0351", 0, 0.000000006 * 2**24, 1, False),
    "HighG 1 Speed": ("0352", 0, 1, 0, False),
    "HighG 1 RPM": ("0353", 0, 1 / 65536, 0, False),
    "HighG 1 PeakG": ("0354", 0, 1, 1, False),
    "HighG 1 Time": ("0355", 0, 0.1, 1, True),
    "HighG 2 Duration(s)": ("0356", 0, 0.000000006 * 2**24, 1, False),
    "HighG 2 Speed": ("0357", 0, 1, 0, False),
    "HighG 2 RPM": ("0358", 0, 1 / 65536, 0, False),
    "HighG 2 PeakG": ("0359", 0, 1, 1, False),
    "HighG 2 Time": ("035A", 0, 0.1, 1, True),
    "HighG 3 Duration(s)": ("035B", 0, 0.000000006 * 2**24, 1, False),
    "HighG 3 Speed": ("035C", 0, 1, 0, False),
    "HighG 3 RPM": ("035D", 0, 1 / 65536, 0, False),
    "HighG 3 PeakG": ("035E", 0, 1, 1, False),
    "HighG 3 Time": ("035F", 0, 0.1, 1, True),
}