# ChirpStack gRPC Configuration
CHIRPSTACK_HOST = "localhost:8088"  # Ensure this is the correct ChirpStack gRPC server address
API_TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJjaGlycHN0YWNrIiwiaXNzIjoiY2hpcnBzdGFjayIsInN1YiI6IjFlMGQzMTAzLTY3ZGMtNGYxMi1iZjRlLTdkY2IyNjI2NDBhZiIsInR5cCI6ImtleSJ9.HxodGM0g8I9Ws8yTYNw8KFa5iP9NEUNvqV1HJVJ60No"  # Replace with your ChirpStack API token

# Not needed
APPLICATION_ID = None  # Remove hardcoded Application ID
TENANT_ID = None  # Replace with your tenant ID
USER_ID = None # Replace with your user ID 

# Pagination Configuration
MAX_DEVICES = 1000
MAX_APPLICATIONS = 1000
MAX_TENANTS = 100
LIMIT = 100
OFFSET = 0

# mqtt
mqtt = "localhost"
keepalive = 60

# Add authorization metadata
AUTH_METADATA = [("authorization", f"Bearer {API_TOKEN}")]

#Automatic Key Rotation Configuration
AUTO_KEY_ROTATION_TIME = 30 * 24 * 60 * 60  # Time in seconds for automatic key rotation

# Join based key rotation
JOIN_SIMULATED_TIME_DELAY = 0.5 * 60  # Time in seconds to simulate join delay

#Uplink Configuration fports
UL_ED_PUBLIC_KEY = 26

# Downlink Configuration fports
DL_UA_PUBLIC_KEY = 76
DL_KEYROTATION_SUCCESS = 10
DL_REBOOT = 52
DL_UPDATE_FREQUENCY = 51
DL_DEVICE_STATUS = 55
DL_LOG_LEVEL = 62
DL_TIME_SYNC = 60
DL_RESET_FACTORY = 61

#API
CONTAINER_EDGEX_SECURITY_PROXY = "edgex-security-proxy-setup"
CONTAINER_CHIRPSTACK = "chirpstack-chirpstack-1"
CONTAINER_VAULT = "edgex-security-secretstore-setup"

VAULT_ROOT_PATH = "/vault/config/assets/resp-init.json"