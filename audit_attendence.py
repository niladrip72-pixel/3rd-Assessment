import csv
import re
import os
import time
import copy
from datetime import datetime, timedelta
from collections import defaultdict          # defaultdict is a dictionary subclass from the collections module that automatically provides a default value for missing keys.

# ==========================================
# 1. CUSTOM EXCEPTIONS
# ==========================================
class InvalidHeaderError(Exception):
    pass

class InvalidTimestampError(Exception):
    pass
# ==========================================
# 2. CONSTANTS
# ==========================================
INPUT_FILE = "raw_punches.csv"
CLEAN_FILE = "clean_punches.csv"
REJECTED_FILE = "rejected_punches.csv"
SUMMARY_FILE = "audit_summary.txt"
REQUIRED_HEADERS = ["employee_id","employee_name","device_ip","punch_type","punch_time","building_code"]
# ==========================================
# 3. DECORATOR
# ==========================================
def execution_time(func):
    def wrapper(*args, **kwargs):
        start_time = time.perf_counter()
        result = func(*args, **kwargs)
        end_time = time.perf_counter()
        print(
            f"Execution Time: " f"{end_time - start_time:.4f} seconds"
        )
        return result
    return wrapper
# ==========================================
# 4. HEADER VALIDATION
# ==========================================
def validate_header(headers):
    actual_headers = [header.strip() if header else "" for header in headers]
    if len(actual_headers) != len(REQUIRED_HEADERS):
        raise InvalidHeaderError("CSV file contains invalid number of columns.")
    if set(actual_headers) != set(REQUIRED_HEADERS):
        raise InvalidHeaderError("CSV file contains invalid headers.")
# ==========================================
# 5. EMPLOYEE ID VALIDATION
# ==========================================
def validate_employee_id(employee_id):
    pattern = r"^E[0-9]{3}$"
    return bool(re.fullmatch(pattern, employee_id))
# ==========================================
# 6. IP ADDRESS VALIDATION
# ==========================================
def validate_ip(device_ip):
    pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    return bool(re.fullmatch(pattern, device_ip))
# ==========================================
# 7. TIMESTAMP VALIDATION
# ==========================================
def validate_timestamp(punch_time):
    try:
        return datetime.strptime(punch_time,"%d-%m-%Y %H:%M:%S")
    except ValueError:
        raise InvalidTimestampError(f"Invalid timestamp: {punch_time}")
# ==========================================
# 8. REUSABLE VALIDATION UTILITY
# ==========================================
def validate_required_values(*args):
    return all(value is not None and str(value).strip() != "" for value in args)
# ==========================================
# 9. READ CSV FILE
# ==========================================
def read_csv():
    if not os.path.exists(INPUT_FILE):
        raise FileNotFoundError(f"{INPUT_FILE} not found")
    with open(INPUT_FILE,"r",newline="",encoding="utf-8") as file:
        reader = csv.DictReader(file)
        validate_header(reader.fieldnames or [])
        rows = list(reader)
    return rows
# ==========================================
# 10. VALIDATE EACH ROW
# ==========================================
def validate_row(row):
    if not validate_required_values(
        row.get("employee_id"),
        row.get("employee_name"),
        row.get("device_ip"),
        row.get("punch_type"),
        row.get("punch_time"),
        row.get("building_code")):
        return False, "Blank required field", None
    employee_id = row["employee_id"].strip()
    device_ip = row["device_ip"].strip()
    punch_type = row["punch_type"].strip().upper()
    if not validate_employee_id(employee_id):
        return False, "Invalid employee ID", None
    if not validate_ip(device_ip):
        return False, "Invalid device IP", None
    if punch_type not in ("IN", "OUT"):
        return False, "Invalid punch type", None
    try:
        punch_datetime = validate_timestamp(row["punch_time"].strip())
    except InvalidTimestampError as error:
        return False, str(error), None
    return True, "Valid", punch_datetime
# ==========================================
# 11. DUPLICATE DETECTION
# ==========================================
def detect_duplicates(rows):
    seen = defaultdict(list)    # It creates a dictionary that stores previously accepted punchtimes.
    duplicates = []
    unique_rows = []
    for row in rows:
        punch_datetime = row["_datetime"]
        key:tuple = (row["employee_id"],row["punch_type"],row["device_ip"])
        previous_punches = seen[key]          # If this key already in seen then we get its previously stored timestamp.  If it doesn't exists , defaultdict(list) automatically creates an empty list.
        is_duplicate:bool = any(abs((punch_datetime - previous_time).total_seconds()) <= 60 for previous_time in previous_punches)
        if is_duplicate:
            row["audit_reason"] = ("Duplicate punch within 60 seconds")
            duplicates.append(row)
        else:
            unique_rows.append(row)
            previous_punches.append(punch_datetime)
    return unique_rows, duplicates
# ==========================================
# 12. DAY ROLLOVER HANDLING
# ==========================================
def handle_day_rollover(rows):
    for row in rows:
        punch_datetime = row["_datetime"]
        if (row["punch_type"] == "OUT" and punch_datetime.hour < 4):
            previous_date = (punch_datetime.date() - timedelta(days=1))
            row["report_date"] = previous_date.strftime("%d-%m-%Y")
            row["rollover"] = "YES"
        else:
            row["report_date"] = (punch_datetime.strftime("%d-%m-%Y"))
            row["rollover"] = "NO"
    return rows
# ==========================================
# 13. SUSPICIOUS BUILDING DETECTION
# ==========================================
def detect_suspicious(rows):
    employee_buildings = defaultdict(set)
    for row in rows:
        key = (row["employee_id"],row["report_date"])
        employee_buildings[key].add(row["building_code"])
    suspicious_keys = {key for key, buildings in employee_buildings.items() if len(buildings) > 1}
    suspicious = []
    clean = []
    for row in rows:
        key = (row["employee_id"],row["report_date"])
        if key in suspicious_keys:
            row["audit_reason"] = ("Employee punched in multiple buildings")
            suspicious.append(row)
        else:
            clean.append(row)
    return clean, suspicious
# ==========================================
# 14. CSV OUTPUT GENERATOR
# ==========================================
def generate_csv(filename, rows, *extra_fields):
    default_fields = REQUIRED_HEADERS.copy()
    fieldnames = default_fields + list(extra_fields)
    with open(filename,"w",newline="",encoding="utf-8") as file:
        writer = csv.DictWriter(file,fieldnames=fieldnames,extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
# ==========================================
# 15. EMPLOYEE-WISE SUMMARY
# ==========================================
def generate_employee_summary(clean,duplicates,suspicious,rejected,**kwargs):
    employee_summary = defaultdict(
        lambda: {
            "clean": 0,
            "duplicate": 0,
            "suspicious": 0,
            "rejected": 0
        }
    )
    groups = {
        "clean": clean,
        "duplicate": duplicates,
        "suspicious": suspicious,
        "rejected": rejected
    }
    for category, records in groups.items():
        for row in records:
            employee_id = row.get("employee_id", "UNKNOWN").strip()
            employee_summary[employee_id][category] += 1
    return dict(sorted(employee_summary.items()))
# ==========================================
# 16. AUDIT SUMMARY REPORT
# ==========================================
def generate_report(original_rows,clean,duplicates,suspicious,rejected):
    employee_summary = generate_employee_summary(clean,duplicates,suspicious,rejected,report_type="attendance")
    with open(SUMMARY_FILE,"w",encoding="utf-8") as file:
        file.write("ATTENDANCE PUNCH AUDIT REPORT\n")
        file.write("=" * 45 + "\n\n")
        file.write(f"Total Rows       : {len(original_rows)}\n")
        file.write(f"Clean Rows       : {len(clean)}\n")
        file.write(f"Duplicate Count  : {len(duplicates)}\n")
        file.write(f"Suspicious Count : {len(suspicious)}\n")
        file.write(f"Rejected Count   : {len(rejected)}\n")
        file.write("\nEMPLOYEE-WISE SUMMARY\n")
        file.write("-" * 45 + "\n")
        for employee_id, counts in employee_summary.items():
            file.write(f"\nEmployee: {employee_id}\n")
            for category, count in counts.items():
                file.write(f"  {category.title():12}: {count}\n")
        file.write("\nDUPLICATE RECORD DETAILS\n")
        for row in duplicates:
            file.write(
                f"{row['employee_id']} - "
                f"{row['punch_time']} - "
                f"{row['audit_reason']}\n"
            )
        file.write("\nSUSPICIOUS RECORD DETAILS\n")
        for row in suspicious:
            file.write(
                f"{row['employee_id']} - "
                f"{row['report_date']} - "
                f"{row['building_code']}\n"
            )
        file.write("\nREJECTED RECORD DETAILS\n")
        for row in rejected:
            file.write(
                f"{row['employee_id']} - "
                f"{row['audit_reason']}\n"
            )

# ==========================================
# 17. MAIN AUDIT FUNCTION
# ==========================================
@execution_time
def audit_attendance():
    try:
        original_rows = read_csv()
        # Shallow copy of original parsed rows
        working_rows = copy.copy(original_rows)

        # Independent row dictionaries
        working_rows = [row.copy() for row in working_rows]
        clean = []
        rejected = []
        valid_rows = []
        duplicates = []
        suspicious = []
        # Validate records
        for row in working_rows:
            is_valid, message, punch_datetime = (validate_row(row))
            if not is_valid:
                row["audit_reason"] = message
                rejected.append(row)
                continue
            row["employee_id"] = (row["employee_id"].strip())
            row["employee_name"] = (row["employee_name"].strip())
            row["device_ip"] = (row["device_ip"].strip())
            row["punch_type"] = (row["punch_type"].strip().upper())
            row["building_code"] = (row["building_code"].strip().upper())
            row["_datetime"] = punch_datetime
            valid_rows.append(row)
        # Detect duplicate punches
        unique_rows, duplicates = detect_duplicates(valid_rows)
        # Handle midnight OUT punches
        unique_rows = handle_day_rollover(unique_rows)
        # Detect suspicious building changes
        clean, suspicious = detect_suspicious(unique_rows)
        # Generate output files
        generate_csv(CLEAN_FILE,clean,"report_date","rollover")
        generate_csv(REJECTED_FILE,rejected,"audit_reason")
        generate_report(original_rows,clean,duplicates,suspicious,rejected)
        print("\nAUDIT COMPLETED SUCCESSFULLY")
        print("Total Rows:", len(original_rows))
        print("Clean Rows:", len(clean))
        print("Duplicate Rows:", len(duplicates))
        print("Suspicious Rows:", len(suspicious))
        print("Rejected Rows:", len(rejected))
    except (FileNotFoundError,InvalidHeaderError,PermissionError,csv.Error) as error:
        print("Audit Error:", error)
# ==========================================
# 18. PROGRAM ENTRY POINT
# ==========================================
if __name__ == "__main__":
    audit_attendance()