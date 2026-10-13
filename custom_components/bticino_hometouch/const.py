"""Constants for the BTicino HOMETOUCH integration."""

DOMAIN = "bticino_hometouch"

# Configuration options
CONF_HOST = "host"
CONF_PORT = "port"
CONF_USERNAME = "username"
CONF_PASSWORD = "password"
CONF_PSW_OPEN = "psw_open"
CONF_GATEWAY_ID = "gateway_id"
CONF_SIP_ACCOUNT = "sip_account"
CONF_SIP_PASSWORD = "sip_password"
CONF_SIP_SERVER = "sip_server"
CONF_CERT_PATH = "cert_path"
CONF_KEY_PATH = "key_path"

CONF_GATE_ADDR = "gate_addr"
CONF_DOOR_ADDR = "door_addr"
CONF_GATE_CID = "gate_cid"
CONF_STREAM_URL = "stream_url"

# Default values
DEFAULT_PORT = 20000
DEFAULT_SIP_PORT = 5061
DEFAULT_SIP_SERVER = "sipserver.bs.iotleg.com"

# Addresses validated on live physical hardware:
# 20: Cancello primario (Serratura/Varco 1)
# 21: Portoncino secondario (Serratura/Varco 2)
DEFAULT_GATE_ADDR = "20"
DEFAULT_DOOR_ADDR = "21"
DEFAULT_GATE_CID = "2009"

# OpenWebNet protocol frames
OWN_ACK = "*#*1##"
OWN_NACK = "*#*0##"
OWN_CMD_SESSION = "*99*0##"
OWN_MONITOR_SESSION = "*99*1##"

# Actuation templates (WHO = 8: Videocitofonia Legrand)
FRAME_DOOR_LOCK_ON = "*8*19*{addr}##"
FRAME_DOOR_LOCK_OFF = "*8*20*{addr}##"
FRAME_GATE_ON = "*8*21*{addr}##"
FRAME_GATE_OFF = "*8*22*{addr}##"
FRAME_STAIR_LIGHT = "*8*23*{addr}##"

# Doorbell call event patterns
OWN_CALL_PATTERN = "*8*40*"
OWN_CALL_END_PATTERN = "*8*41*"

# Platforms supported
PLATFORMS = ["lock", "button", "binary_sensor", "camera"]
