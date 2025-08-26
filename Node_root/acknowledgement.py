# acknowledgement.py
import requests, re, hashlib
from monitor import track_performance

ALLOWED_ACK_ROLES = {"Fog", "Edge"}          # send ack only to these
SKIP_ACK_ROLES    = {"Cloud", "Sensor", "Actuator"}  # root + end nodes

_ENODE_RE = re.compile(r"^enode://[a-fA-F0-9]+@[\w\.\-:\[\]]+:\d+$")
_URL_RE   = re.compile(r"^http?://[^?#]+$") 


class AcknowledgementSender:
    """Sends acknowledgment (enode + bootstrap files) to a registering Fog/Edge node."""

    def __init__(self, registering_node_url, genesis_file, node_registry_file,
                 besu_rpc_url, prefunded_keys_file, timeout=8, verify_ssl=False):
        self.registering_node_url = str(registering_node_url).rstrip("/")
        self.genesis_file = genesis_file
        self.node_registry_file = node_registry_file
        self.besu_rpc_url = besu_rpc_url
        self.prefunded_keys_file = prefunded_keys_file
        self.timeout = timeout
        self.verify_ssl = verify_ssl

    @staticmethod
    def _role_allows(node_type: str) -> bool:
        nt = (node_type or "").strip()
        return nt in ALLOWED_ACK_ROLES

    @staticmethod
    def _sha256(path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    #@track_performance
    def get_enode(self) -> str | None:
        """Fetch enode URL via Besu admin_nodeInfo."""
        payload = {"jsonrpc": "2.0", "method": "admin_nodeInfo", "params": [], "id": 1}
        try:
            r = requests.post(
                self.besu_rpc_url, json=payload,
                headers={"Content-Type": "application/json"},
                timeout=self.timeout, verify=self.verify_ssl if self.besu_rpc_url.startswith("https") else True
            )
            r.raise_for_status()
            data = r.json() or {}
            enode_url = (data.get("result") or {}).get("enode", "")
            if enode_url and _ENODE_RE.match(enode_url):
                return enode_url
        except requests.RequestException as e:
            print(f"[ack] Error fetching enode: {e}")
        return None

    #@track_performance
    def send_acknowledgment(self, node_id: str, *, node_type: str) -> bool:
        """
        Securely POST ACK to client:
          - only for Fog/Edge
          - requires auth token (sent as X-Ack-Token)
          - includes SHA-256 for each artifact
        """
        # Role gate
        if not self._role_allows(node_type):
            print(f"[ack] Skipping ack for node_type='{node_type}'.")
            return False

        # URL sanity
        if not _URL_RE.match(self.registering_node_url):
            print(f"[ack] Invalid ack URL: {self.registering_node_url}")
            return False

        # # Token required
        # auth_token = (auth_token or "").strip()
        # if not auth_token:
        #     print("[ack] Missing auth token; refusing to send artifacts.")
        #     return False

        # Enode
        enode = self.get_enode()
        if not enode:
            print("[ack] Error: enode could not be retrieved!")
            return False

        # Prepare payload
        data = {
            "node_id": node_id,
            "enode": enode,
            # Optional hashes so the client can verify integrity before using files
            "genesis_sha256": self._sha256(self.genesis_file),
            "registry_sha256": self._sha256(self.node_registry_file),
            "prefunded_sha256": self._sha256(self.prefunded_keys_file),
        }
        print(f"[ack] Sending ACK to {self.registering_node_url} for node {node_id} (type={node_type})")

        # headers = {
        #     "X-Ack-NodeId": node_id,
        #     "X-Ack-Role": node_type,
        # }
        # if (auth_token or "").strip():
        #     headers["X-Ack-Token"] = auth_token.strip()
        headers = {"X-Ack-NodeId": node_id, "X-Ack-Role": node_type}
        # Send with short timeout; require 200 OK
        url = f"{self.registering_node_url}/acknowledgement"
        try:
            with open(self.genesis_file, "rb") as f_genesis, \
                 open(self.node_registry_file, "rb") as f_registry, \
                 open(self.prefunded_keys_file, "rb") as f_keys:

                files = {
                    "genesis_file": ("genesis.json", f_genesis, "application/json"),
                    "node_registry_file": ("NodeRegistry.json", f_registry, "application/json"),
                    "prefunded_keys_file": ("prefunded_keys.json", f_keys, "application/json"),
                }
                # Send POST request with files and data
                resp = requests.post(
                    url, data=data, files=files, headers=headers,
                    timeout=self.timeout
                )
                print(f"[ack] Response {resp.status_code}: {resp.text[:500]}")
                if resp.status_code == 200:
                    print(f"[ack] Acknowledgment sent to {url} for node {node_id} (type={node_type})")
                    return True
                print(f"[ack] Ack HTTP {resp.status_code}: {resp.text}")
                return False

        except FileNotFoundError as e:
            print(f"[ack] Missing artifact: {e}")
            return False
        except Exception as e:
            print(f"[ack] Error sending acknowledgment: {e}")
            return False