MAX_UPLOAD_BYTES = 10 * 1024 * 1024
ANALYSIS_SCHEMA_VERSION = "1.0"
CANON_VERSION = "cj/1"
REQUIRED_SHEET = "SIEM Export"
REQUIRED_COLUMNS = (
    "Log_ID",
    "Timestamp",
    "Hostname",
    "Event_ID",
    "User",
    "Source_IP",
    "Destination",
    "Log_Source",
    "Event_Description",
    "Process_CommandLine",
    "Result",
    "Severity",
)
