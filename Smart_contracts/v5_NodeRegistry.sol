// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/**
 * Stack-safe & size-reduced:
 * - Custom errors (cheap).
 * - Packed structs.
 * - No storage-alias locals in hot paths.
 * - Direct mapping field reads/writes.
 * - Short-lived temps only.
 * - Fewer event args: GrantIssued/GrantRevoked use grantId only.
 * - PolicyDeprecatedEvent (event) vs PolicyDeprecated() (error) to avoid clashes.
 */
contract NodeRegistry {
    // -------- Ops bitmask --------
    uint8 private constant OP_READ   = 1 << 0; // 1
    uint8 private constant OP_WRITE  = 1 << 1; // 2
    uint8 private constant OP_UPDATE = 1 << 2; // 4
    uint8 private constant OP_REMOVE = 1 << 3; // 8

    // -------- Custom errors --------
    error NotPolicyAdmin();
    error NotResourceOwner();
    error InvalidRoles();
    error EmptyOpsAllowed();
    error PolicyNotFound();
    error PolicyDeprecated();
    error PolicyRoleMismatch();
    error EmptyOpsSubset();
    error InvalidExpiry();
    error GrantAlreadyActive();
    error NodeNotRegistered();
    error DuplicateSignature();
    error AddressNotRegistered();
    error ZeroAddr();

    // -------- Types --------
    enum NodeType { Unknown, Cloud, Fog, Edge, Sensor, Actuator }

    struct IoTNode {
        string   nodeName;
        NodeType nodeType;
        string   publicKey;
        bool     isRegistered;
        address  registeredBy;
        NodeType registeredByNodeType;
        string   nodeSignature;
    }

    struct Policy {
        // tightly packed header
        NodeType fromRole;     // 1 byte
        NodeType toRole;       // 1 byte
        uint8    opsAllowed;   // 1 byte
        bool     isDeprecated; // 1 byte
        // 4-byte boundary
        bytes32  ctxSchema;    // 32
        bytes32  policyHash;   // 32
        uint32   version;      // 4
        // ~72 bytes
    }

    struct CapabilityGrant {
        uint64 issuedAt;     // 8
        uint64 expiresAt;    // 8
        uint32 policyId;     // 4
        uint8  opsSubset;    // 1
        bool   isIssued;     // 1
        bool   isRevoked;    // 1
        // ~23 bytes
    }

    // -------- Storage --------
    mapping(string => IoTNode) public iotNodes;
    mapping(string => string)  public nodeSignatureToNodeId;
    mapping(address => string) public addressToNodeId;
    mapping(address => string) public nodeRpcUrls;

    mapping(uint256 => Policy) public policies;
    uint256 public nextPolicyId;
    address public policyAdmin;

    mapping(bytes32 => CapabilityGrant) public grants;

    // -------- Events --------
    event ValidatorProposed(address indexed proposedBy, address indexed validator);
    event RpcUrlMapped(address indexed nodeAddress, string rpcURL);

    event NodeRegistered(
        string indexed nodeId,
        string nodeName,
        NodeType nodeType,
        string publicKey,
        address registeredBy,
        NodeType registeredByNodeType,
        string nodeSignature
    );

    event PolicyCreated(
        uint256 indexed policyId,
        NodeType fromRole,
        NodeType toRole,
        uint8 opsAllowed,
        bytes32 ctxSchema,
        uint32 version,
        bytes32 policyHash
    );
    event PolicyUpdated(
        uint256 indexed policyId,
        uint32 version,
        uint8 opsAllowed,
        bytes32 ctxSchema,
        bytes32 policyHash
    );
    event PolicyDeprecatedEvent(uint256 indexed policyId);
    event PolicyChanged(uint256 indexed policyId, uint32 version);

    event GrantIssued(bytes32 indexed grantId);
    event GrantRevoked(bytes32 indexed grantId);

    constructor() {
        policyAdmin = msg.sender;
    }

    // =========================================================
    //                       NODE REGISTRATION
    // =========================================================
    /// @notice Register a node using a packed ABI payload to avoid stack-too-deep.
    /// @dev payload is abi.encode(
    ///   string nodeId,
    ///   string nodeName,
    ///   string nodeTypeStr,
    ///   string publicKey,
    ///   address registeredBy,
    ///   string rpcURL,
    ///   string registeredByNodeTypeStr,
    ///   string nodeSignature
    /// )
    function registerNodePacked(bytes calldata payload) external {
        (
            string memory nodeId,
            string memory nodeName,
            string memory nodeTypeStr,
            string memory publicKey,
            address registeredBy,
            string memory rpcURL,
            string memory registeredByNodeTypeStr,
            string memory nodeSignature
        ) = abi.decode(
            payload,
            (string,string,string,string,address,string,string,string)
        );

        if (registeredBy == address(0)) revert ZeroAddr();
        if (bytes(nodeSignatureToNodeId[nodeSignature]).length != 0) revert DuplicateSignature();

        // bind signature -> id early (cheap)
        nodeSignatureToNodeId[nodeSignature] = nodeId;

        // limit variable lifetimes using tight scopes & small helpers
        (NodeType nodeType, NodeType regByNodeType) = _parseRoles(nodeTypeStr, registeredByNodeTypeStr);

        _setNodeHeader(nodeId, nodeName, nodeType);
        _setNodeTail(
            nodeId,
            publicKey,
            registeredBy,
            regByNodeType,
            nodeSignature,
            rpcURL
        );
    }

    /// @notice Returns true if a nodeSignature is known and maps to a registered node.
    function isNodeRegistered(string calldata nodeSignature) external view returns (bool) {
        string memory nodeId = nodeSignatureToNodeId[nodeSignature];
        if (bytes(nodeId).length == 0) return false;                 // unknown signature
        if (!iotNodes[nodeId].isRegistered) return false;            // not registered
        // ensure the stored signature matches exactly
        return keccak256(abi.encodePacked(iotNodes[nodeId].nodeSignature))
            == keccak256(abi.encodePacked(nodeSignature));
    }
    function proposeValidator(address validator) external {
        if (validator == address(0)) revert ZeroAddr();
        emit ValidatorProposed(msg.sender, validator);
    }

    // -------- internal helpers to keep stack shallow --------
    function _parseRoles(
        string memory nodeTypeStr,
        string memory registeredByNodeTypeStr
    ) private pure returns (NodeType nodeType, NodeType regByNodeType) {
        NodeType t1 = getNodeType(nodeTypeStr);
        if (t1 == NodeType.Unknown) revert InvalidRoles();
        NodeType t2 = getNodeType(registeredByNodeTypeStr);
        if (t2 == NodeType.Unknown) revert InvalidRoles();
        return (t1, t2);
    }

    function _setNodeHeader(
        string memory nodeId,
        string memory nodeName,
        NodeType nodeType
    ) private {
        iotNodes[nodeId].nodeName = nodeName;
        iotNodes[nodeId].nodeType = nodeType;
    }

    function _setNodeTail(
        string memory nodeId,
        string memory publicKey,
        address registeredBy,
        NodeType registeredByNodeType,
        string memory nodeSignature,
        string memory rpcURL
    ) private {
        iotNodes[nodeId].publicKey = publicKey;
        iotNodes[nodeId].isRegistered = true;
        iotNodes[nodeId].registeredBy = registeredBy;
        iotNodes[nodeId].registeredByNodeType = registeredByNodeType;
        iotNodes[nodeId].nodeSignature = nodeSignature;

        addressToNodeId[registeredBy] = nodeId;
        nodeRpcUrls[registeredBy] = rpcURL;

        emit RpcUrlMapped(registeredBy, rpcURL);
        emit NodeRegistered(
            nodeId,
            iotNodes[nodeId].nodeName,
            iotNodes[nodeId].nodeType,
            publicKey,
            registeredBy,
            registeredByNodeType,
            nodeSignature
        );
    }

    function getNodeDetailsBySignature(string calldata nodeSignature)
        external
        view
        returns (
            string memory,
            string memory,
            NodeType,
            string memory,
            bool,
            address,
            string memory,
            NodeType
        )
    {
        string memory nodeId = nodeSignatureToNodeId[nodeSignature];

        if (
            !iotNodes[nodeId].isRegistered ||
            keccak256(abi.encodePacked(iotNodes[nodeId].nodeSignature)) !=
                keccak256(abi.encodePacked(nodeSignature))
        ) {
            revert NodeNotRegistered();
        }

        return (
            nodeId,
            iotNodes[nodeId].nodeName,
            iotNodes[nodeId].nodeType,
            iotNodes[nodeId].publicKey,
            iotNodes[nodeId].isRegistered,
            iotNodes[nodeId].registeredBy,
            iotNodes[nodeId].nodeSignature,
            iotNodes[nodeId].registeredByNodeType
        );
    }

    function getNodeDetailsByAddress(address nodeAddress)
        external
        view
        returns (
            string memory,
            string memory,
            NodeType,
            string memory,
            bool,
            address,
            string memory,
            NodeType
        )
    {
        string memory nodeId = addressToNodeId[nodeAddress];
        if (bytes(nodeId).length == 0) revert AddressNotRegistered();

        return (
            nodeId,
            iotNodes[nodeId].nodeName,
            iotNodes[nodeId].nodeType,
            iotNodes[nodeId].publicKey,
            iotNodes[nodeId].isRegistered,
            iotNodes[nodeId].registeredBy,
            iotNodes[nodeId].nodeSignature,
            iotNodes[nodeId].registeredByNodeType
        );
    }

    // =========================================================
    //                         POLICY REGISTRY
    // =========================================================
    modifier onlyPolicyAdmin() {
        if (msg.sender != policyAdmin) revert NotPolicyAdmin();
        _;
    }

    function setPolicyAdmin(address newAdmin) external onlyPolicyAdmin {
        if (newAdmin == address(0)) revert ZeroAddr();
        policyAdmin = newAdmin;
    }

    function _computePolicyHash(
        NodeType fromRole,
        NodeType toRole,
        uint8 opsAllowed,
        bytes32 ctxSchema
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(fromRole, toRole, opsAllowed, ctxSchema));
    }

    function createPolicy(
        NodeType fromRole,
        NodeType toRole,
        uint8 opsAllowed,
        bytes32 ctxSchema
    ) external onlyPolicyAdmin returns (uint256 policyId) {
        if (fromRole == NodeType.Unknown || toRole == NodeType.Unknown) revert InvalidRoles();
        if (opsAllowed == 0) revert EmptyOpsAllowed();

        unchecked {
            policyId = ++nextPolicyId;
        }

        policies[policyId].fromRole    = fromRole;
        policies[policyId].toRole      = toRole;
        policies[policyId].opsAllowed  = opsAllowed;
        policies[policyId].isDeprecated = false;
        policies[policyId].ctxSchema   = ctxSchema;
        policies[policyId].policyHash  = _computePolicyHash(fromRole, toRole, opsAllowed, ctxSchema);
        policies[policyId].version     = 1;

        emit PolicyCreated(policyId, fromRole, toRole, opsAllowed, ctxSchema, 1, policies[policyId].policyHash);
        emit PolicyChanged(policyId, 1);
    }

    function updatePolicy(uint256 policyId, uint8 opsAllowed, bytes32 ctxSchema) external onlyPolicyAdmin {
        if (policies[policyId].version == 0) revert PolicyNotFound();
        if (policies[policyId].isDeprecated) revert PolicyDeprecated();
        if (opsAllowed == 0) revert EmptyOpsAllowed();

        policies[policyId].opsAllowed = opsAllowed;
        policies[policyId].ctxSchema  = ctxSchema;
        unchecked {
            policies[policyId].version += 1;
        }
        policies[policyId].policyHash =
            _computePolicyHash(policies[policyId].fromRole, policies[policyId].toRole, opsAllowed, ctxSchema);

        emit PolicyUpdated(
            policyId,
            policies[policyId].version,
            policies[policyId].opsAllowed,
            policies[policyId].ctxSchema,
            policies[policyId].policyHash
        );
        emit PolicyChanged(policyId, policies[policyId].version);
    }

    function deprecatePolicy(uint256 policyId) external onlyPolicyAdmin {
        if (policies[policyId].version == 0) revert PolicyNotFound();
        if (policies[policyId].isDeprecated) revert PolicyDeprecated();
        policies[policyId].isDeprecated = true;
        emit PolicyDeprecatedEvent(policyId);
        emit PolicyChanged(policyId, policies[policyId].version);
    }

    function getPolicy(uint256 policyId) external view returns (Policy memory) {
        return policies[policyId];
    }

    // =========================================================
    //                 GRANTS (RESOURCE-OWNER ONLY)
    // =========================================================
    function issueGrant(
        string calldata fromNodeSignature,
        string calldata toNodeSignature,
        uint256 policyId,
        uint8 opsSubset,
        uint64 expiresAt
    ) external {
        string memory fromNodeId = nodeSignatureToNodeId[fromNodeSignature];
        string memory toNodeId   = nodeSignatureToNodeId[toNodeSignature];

        if (!iotNodes[fromNodeId].isRegistered || !iotNodes[toNodeId].isRegistered) revert NodeNotRegistered();
        if (msg.sender != iotNodes[toNodeId].registeredBy) revert NotResourceOwner();

        if (policies[policyId].version == 0) revert PolicyNotFound();
        if (policies[policyId].isDeprecated) revert PolicyDeprecated();

        if (policies[policyId].fromRole != iotNodes[fromNodeId].nodeType ||
            policies[policyId].toRole   != iotNodes[toNodeId].nodeType) revert PolicyRoleMismatch();

        if (opsSubset == 0) revert EmptyOpsSubset();
        if ((opsSubset & ~policies[policyId].opsAllowed) != 0) revert EmptyOpsAllowed();
        if (expiresAt <= uint64(block.timestamp)) revert InvalidExpiry();

        bytes32 grantId = keccak256(abi.encodePacked(fromNodeSignature, toNodeSignature));
        if (grants[grantId].isIssued && !grants[grantId].isRevoked) revert GrantAlreadyActive();

        grants[grantId].policyId  = uint32(policyId);
        grants[grantId].opsSubset = opsSubset;
        grants[grantId].issuedAt  = uint64(block.timestamp);
        grants[grantId].expiresAt = expiresAt;
        grants[grantId].isIssued  = true;
        grants[grantId].isRevoked = false;

        emit GrantIssued(grantId);
    }

    function revokeGrant(string calldata fromNodeSignature, string calldata toNodeSignature) external {
        bytes32 grantId = keccak256(abi.encodePacked(fromNodeSignature, toNodeSignature));

        string memory toNodeId = nodeSignatureToNodeId[toNodeSignature];
        if (msg.sender != iotNodes[toNodeId].registeredBy) revert NotResourceOwner();

        if (!grants[grantId].isIssued) revert PolicyNotFound();     // use as "grant not found"
        if (grants[grantId].isRevoked) revert GrantAlreadyActive(); // use as "already revoked"

        grants[grantId].isRevoked = true;
        emit GrantRevoked(grantId);
    }

    function getGrant(string calldata fromNodeSignature, string calldata toNodeSignature)
        external
        view
        returns (uint256 policyId, uint8 opsSubset, uint64 issuedAt, uint64 expiresAt, bool isIssued, bool isRevoked)
    {
        bytes32 grantId = keccak256(abi.encodePacked(fromNodeSignature, toNodeSignature));
        return (
            grants[grantId].policyId,
            grants[grantId].opsSubset,
            grants[grantId].issuedAt,
            grants[grantId].expiresAt,
            grants[grantId].isIssued,
            grants[grantId].isRevoked
        );
    }

    function checkGrant(
        string calldata fromNodeSignature,
        string calldata toNodeSignature,
        uint8 opBit
    ) external view returns (bool) {
        bytes32 grantId = keccak256(abi.encodePacked(fromNodeSignature, toNodeSignature));

        CapabilityGrant storage g = grants[grantId];
        if (!g.isIssued || g.isRevoked) return false;
        if (uint64(block.timestamp) > g.expiresAt) return false;

        uint256 pid = g.policyId;                 // ✅ use the policyId from the grant
        Policy storage p = policies[pid];
        if (p.version == 0 || p.isDeprecated) return false;

        if ((g.opsSubset & opBit) == 0) return false;
        if ((p.opsAllowed & opBit) == 0) return false;

        return true;
    }

    function isGrantExpired(string calldata fromNodeSignature, string calldata toNodeSignature)
        external
        view
        returns (bool)
    {
        bytes32 grantId = keccak256(abi.encodePacked(fromNodeSignature, toNodeSignature));
        if (!grants[grantId].isIssued || grants[grantId].isRevoked) return true;
        return (uint64(block.timestamp) > grants[grantId].expiresAt);
    }

    // =========================================================
    //                         HELPERS
    // =========================================================
    function getNodeType(string memory nodeTypeStr) internal pure returns (NodeType) {
        bytes32 h = keccak256(abi.encodePacked(nodeTypeStr));
        if (h == keccak256(abi.encodePacked("Cloud")))    return NodeType.Cloud;
        if (h == keccak256(abi.encodePacked("Fog")))      return NodeType.Fog;
        if (h == keccak256(abi.encodePacked("Edge")))     return NodeType.Edge;
        if (h == keccak256(abi.encodePacked("Sensor")))   return NodeType.Sensor;
        if (h == keccak256(abi.encodePacked("Actuator"))) return NodeType.Actuator;
        return NodeType.Unknown;
    }

    function isValidator(string calldata nodeSignature) external view returns (bool) {
        string memory nodeId = nodeSignatureToNodeId[nodeSignature];

        if (
            !iotNodes[nodeId].isRegistered ||
            keccak256(abi.encodePacked(iotNodes[nodeId].nodeSignature)) !=
                keccak256(abi.encodePacked(nodeSignature))
        ) {
            revert NodeNotRegistered();
        }

        NodeType t = iotNodes[nodeId].nodeType;
        return (t == NodeType.Cloud || t == NodeType.Fog);
    }
}