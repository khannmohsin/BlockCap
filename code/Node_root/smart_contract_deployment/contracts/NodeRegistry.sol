// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

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
    error PolicyIsDeprecated();
    error PolicyRoleMismatch();
    error EmptyOpsSubset();
    error InvalidExpiry();
    error GrantAlreadyActive();
    error NodeNotRegistered();
    error DuplicateSignature();
    error AddressNotRegistered();
    error ZeroAddr();
    error DuplicatePolicy();
    error DuplicateNodeId();
    error OpsSubsetExceedsAllowed();
    error NotGrantHolder();
    error AlreadyRevoked();
    error InvalidDelegationDepth();

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
        NodeType fromRole;
        NodeType toRole;
        uint8    opsAllowed;
        bool     isDeprecated;
        bytes32  ctxSchema;
        bytes32  policyHash;
        uint32   version;
    }

    struct CapabilityGrant {
        uint64 issuedAt;
        uint64 expiresAt;
        uint32 policyId;
        uint8  opsSubset;
        bool   isIssued;
        bool   isRevoked;
        bool   delegationAllowed;
        uint8  delegationDepth;
        bytes32 parentGrantId; // NEW: linkage for delegated grants
        uint8  depthDel;
        bytes32 parentTokenId;
        // Generation identity (root-soundness fix): a (from,to,policyId)
        // triple names a fixed, reusable storage slot, not a unique
        // issuance. `generation` counts how many times THIS slot has been
        // freshly (re-)issued from an inactive state; a re-issue after
        // revocation bumps it. `parentGeneration` records the parent
        // slot's generation at the moment THIS grant was created/last
        // (re-)delegated. The ancestor walk in _evaluateGrant compares a
        // parent's current generation against what each descendant
        // recorded, so revoking a grant and later re-granting the same
        // triple to an unrelated purpose no longer silently re-validates
        // stale descendants that were delegated from the original grant.
        uint32 generation;
        uint32 parentGeneration;
    }

    // -------- Storage --------
    mapping(string => IoTNode) public iotNodes;            // nodeId => details
    mapping(string => string)  public nodeSignatureToNodeId;
    mapping(address => string) public addressToNodeId;
    mapping(address => string) public nodeRpcUrls;

    // Registration proves only that the caller controls the address it
    // names (caller equality) -- it is not, by itself, authorization to
    // join QBFT consensus. A self-registered node that also requests
    // validator status must be separately admitted by policyAdmin before
    // any node's validator-proposal listener will vote for it.
    mapping(address => bool) public validatorAdmissionApproved;

    mapping(uint256 => Policy) public policies;
    uint256 public nextPolicyId;
    address public policyAdmin;

    // Keyed by keccak256(abi.encode(fromSig, toSig, policyId))
    mapping(bytes32 => CapabilityGrant) public grants;
    mapping(bytes32 => CapabilityGrant) private grantsByTokenId;

    // policyHash -> policyId (for duplicate detection)
    mapping(bytes32 => uint256) public policyIdByHash;

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

    event NodeOwnershipTransferred(string indexed nodeId, address indexed previousOwner, address indexed newOwner);
    event ValidatorAdmissionApproved(address indexed candidate, address indexed approvedBy);
    event ValidatorAdmissionRevoked(address indexed candidate, address indexed revokedBy);

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
    event PolicyDeprecated(uint256 indexed policyId);
    event PolicyDeprecatedEvent(uint256 indexed policyId);
    event PolicyChanged(uint256 indexed policyId, uint32 version);

    event GrantIssued(bytes32 indexed grantId);
    event GrantExtended(bytes32 indexed grantId, uint64 newExpiresAt, uint8 newOpsSubset);
    event GrantRevoked(bytes32 indexed grantId);
    event GrantDelegated(bytes32 indexed parentGrantId, bytes32 indexed grantId, uint8 depthRemaining);
    event AccessDenied(address indexed from, address indexed to, bytes32 indexed policyId, uint8 op, string reason, uint256 timestamp);
    event AccessGranted(address indexed from, address indexed to, bytes32 indexed policyId, uint8 op, uint256 timestamp);

    // ============== MULTISIG CONFIG (STATE + EVENTS) ==============
    bool public msigRequired;                     // on/off switch
    mapping(address => bool) public msigApprover; // who can approve
    uint8  public msigApproverCount;
    uint8  public msigThreshold;                  // 1..approverCount

    // action approvals: createPolicy, and (R07 fix) updatePolicy widening
    // and disabling an active msigRequired -- an admin's two previously
    // unilateral ways to defeat the "admin can only subtract, never grant"
    // guarantee. Keyed generically since each key is domain-tagged
    // separately below; no collision risk across action types.
    mapping(bytes32 => uint256) private msigApprovalsCount;
    mapping(bytes32 => mapping(address => bool)) private msigApprovedBy;

    // Per-action-type nonce lives in msigActionNonce (declared with the
    // shared approval helpers below), keyed by action tag rather than one
    // state variable per action.

    event MsigModeSet(bool required);
    event MsigApproverAdded(address indexed approver);
    event MsigApproverRemoved(address indexed approver);
    event MsigThresholdSet(uint8 threshold);
    event MsigApproved(bytes32 indexed actionKey, address indexed approver, uint256 approvals);
    event MsigCleared(bytes32 indexed actionKey);

    constructor() {
        policyAdmin = msg.sender;
    }

    // =========================================================
    //                       NODE REGISTRATION
    // =========================================================
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
        if (msg.sender != registeredBy) revert NotResourceOwner(); // Harden: only the registering owner can submit
        if (bytes(iotNodes[nodeId].nodeName).length != 0 && iotNodes[nodeId].isRegistered) revert DuplicateNodeId();
        if (bytes(nodeSignatureToNodeId[nodeSignature]).length != 0) revert DuplicateSignature();

        nodeSignatureToNodeId[nodeSignature] = nodeId;

        (NodeType nodeType, NodeType regByNodeType) = _parseRoles(nodeTypeStr, registeredByNodeTypeStr);

        _setNodeHeader(nodeId, nodeName, nodeType);
        _setNodeTail(nodeId, publicKey, registeredBy, regByNodeType, nodeSignature, rpcURL);
    }

    function transferNodeOwnership(string calldata nodeId, address newOwner) external {
        if (newOwner == address(0)) revert ZeroAddr();
        if (!iotNodes[nodeId].isRegistered) revert NodeNotRegistered();
        address prev = iotNodes[nodeId].registeredBy;
        if (msg.sender != prev) revert NotResourceOwner();

        // update owner
        iotNodes[nodeId].registeredBy = newOwner;

        // clear old reverse index and set new one
        addressToNodeId[prev] = "";
        addressToNodeId[newOwner] = nodeId;

        // carry over rpcURL mapping (if any) to new owner address
        string memory url = nodeRpcUrls[prev];
        if (bytes(url).length != 0) {
            nodeRpcUrls[newOwner] = url;
            emit RpcUrlMapped(newOwner, url);
        }

        emit NodeOwnershipTransferred(nodeId, prev, newOwner);
    }

    function isNodeRegistered(string calldata nodeSignature) external view returns (bool) {
        string memory nodeId = nodeSignatureToNodeId[nodeSignature];
        if (bytes(nodeId).length == 0) return false;
        if (!iotNodes[nodeId].isRegistered) return false;
        return keccak256(abi.encodePacked(iotNodes[nodeId].nodeSignature))
            == keccak256(abi.encodePacked(nodeSignature));
    }

    function proposeValidator(address validator) external {
        if (validator == address(0)) revert ZeroAddr();
        // Candidacy is self-proposed by a registered address owner. Admission
        // is the separate QBFT validator vote/membership transition, not a
        // policy-administrator decision or a Cloud/Fog role label.
        if (msg.sender != validator || bytes(addressToNodeId[validator]).length == 0) revert NotResourceOwner();
        emit ValidatorProposed(msg.sender, validator);
    }

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
        ) revert NodeNotRegistered();

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

    // ---------- Validator admission (registrar) ----------
    // Registration (registerNodePacked) only proves the caller controls the
    // address it names; it does not establish that address is fit to join
    // QBFT consensus. Any node requesting validator status must be
    // separately, explicitly admitted here by policyAdmin before other
    // nodes' validator-proposal listeners will vote for it -- closing the
    // gap where a self-registered, unvetted identity could request
    // validator status and be admitted purely because it was registered.
    function approveValidatorAdmission(address candidate) external onlyPolicyAdmin {
        if (candidate == address(0)) revert ZeroAddr();
        // Deliberately does NOT additionally require
        // addressToNodeId[candidate] to be set: that mapping is keyed by
        // registeredBy, an administrative/owning address that this
        // project's registration flow can set to a shared registrar
        // account rather than the candidate's own consensus/P2P identity
        // -- it would reject exactly the addresses this function exists to
        // approve. policyAdmin's explicit approval is itself the intended
        // authorization act (decision 4: validator membership is separate
        // from any role label or registration record), not a check against
        // a mapping that does not track consensus identities at all.
        validatorAdmissionApproved[candidate] = true;
        emit ValidatorAdmissionApproved(candidate, msg.sender);
    }

    function revokeValidatorAdmission(address candidate) external onlyPolicyAdmin {
        validatorAdmissionApproved[candidate] = false;
        emit ValidatorAdmissionRevoked(candidate, msg.sender);
    }

    function setPolicyAdmin(address newAdmin) external onlyPolicyAdmin {
        if (newAdmin == address(0)) revert ZeroAddr();
        policyAdmin = newAdmin;
    }

    // ---------- Multisig config (admin) ----------
    // Generic approval mechanism shared by every gated admin action
    // (createPolicy, updatePolicy widening, disabling an active
    // msigRequired). One nonce per action tag, stored in a mapping instead
    // of a separate state variable per action, so this logic exists once in
    // bytecode rather than once per action -- this contract is close to the
    // EIP-170 24576-byte deploy limit, so shared internal functions here are
    // load-bearing, not just style.
    mapping(bytes32 => uint256) private msigActionNonce;

    function _msigKey(bytes32 tag, bytes32 paramsHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(tag, msigActionNonce[tag], paramsHash));
    }

    function _msigApprove(bytes32 tag, bytes32 paramsHash) internal {
        if (!msigApprover[msg.sender]) revert NotPolicyAdmin();
        bytes32 k = _msigKey(tag, paramsHash);
        if (msigApprovedBy[k][msg.sender]) revert GrantAlreadyActive();
        msigApprovedBy[k][msg.sender] = true;
        uint256 cnt = msigApprovalsCount[k] + 1;
        msigApprovalsCount[k] = cnt;
        emit MsigApproved(k, msg.sender, cnt);
    }

    // Consumes approvals for (tag, paramsHash) if msigRequired; no-op
    // otherwise. `force` bypasses the msigRequired short-circuit for gates
    // that must apply even when evaluated from within setMsigMode itself
    // (disabling msig while it is still active).
    function _msigRequireAndClear(bytes32 tag, bytes32 paramsHash, bool force) internal {
        if (!force && !msigRequired) return;
        bytes32 k = _msigKey(tag, paramsHash);
        if (msigThreshold == 0 || msigApproverCount == 0) revert PolicyNotFound();
        if (msigApprovalsCount[k] < msigThreshold) revert PolicyNotFound();
        unchecked { msigActionNonce[tag] += 1; }
        msigApprovalsCount[k] = 0;
        emit MsigCleared(k);
    }

    bytes32 private constant TAG_CREATE_POLICY  = keccak256("CREATE_POLICY");
    bytes32 private constant TAG_UPDATE_POLICY  = keccak256("UPDATE_POLICY");
    bytes32 private constant TAG_DISABLE_MSIG   = keccak256("DISABLE_MSIG");
    bytes32 private constant TAG_ADD_APPROVER   = keccak256("ADD_APPROVER");
    bytes32 private constant TAG_REMOVE_APPROVER = keccak256("REMOVE_APPROVER");
    bytes32 private constant TAG_SET_THRESHOLD  = keccak256("SET_THRESHOLD");

    // One configuration approval entry point avoids duplicating wrappers in
    // bytecode. `paramsHash` is keccak256(abi.encodePacked(address)) for
    // add/remove and keccak256(abi.encodePacked(uint8)) for threshold.
    function approveMsigConfig(bytes32 tag, bytes32 paramsHash) external {
        if (tag != TAG_ADD_APPROVER && tag != TAG_REMOVE_APPROVER && tag != TAG_SET_THRESHOLD) {
            revert InvalidRoles();
        }
        _msigApprove(tag, paramsHash);
    }

    function approveDisableMsig() external {
        _msigApprove(TAG_DISABLE_MSIG, bytes32(0));
    }

    function setMsigMode(bool required) external onlyPolicyAdmin {
        // Turning multisig ON unilaterally is safe (it only adds a check);
        // turning an ACTIVE requirement OFF is not -- a lone admin must not
        // be able to remove the very protection msigRequired provides just
        // by flipping this switch. Route that specific transition through
        // the same approval mechanism createPolicy already uses.
        if (!required && msigRequired) {
            _msigRequireAndClear(TAG_DISABLE_MSIG, bytes32(0), true);
        }
        // Do not advertise quorum protection with a one-person quorum. The
        // bootstrap administrator may assemble the initial membership while
        // mode is off, but activation needs an actual independent quorum.
        if (required && !msigRequired && (msigApproverCount < 2 || msigThreshold < 2)) {
            revert InvalidRoles();
        }
        msigRequired = required;
        emit MsigModeSet(required);
    }

    function addMsigApprover(address a) external onlyPolicyAdmin {
        if (a == address(0) || msigApprover[a]) revert NotPolicyAdmin(); // reuse admin guard; bad arg treated as admin error
        if (msigRequired) {
            _msigRequireAndClear(TAG_ADD_APPROVER, keccak256(abi.encodePacked(a)), true);
        }
        msigApprover[a] = true;
        unchecked { msigApproverCount += 1; }
        if (msigThreshold == 0) msigThreshold = 1;
        emit MsigApproverAdded(a);
    }

    function removeMsigApprover(address a) external onlyPolicyAdmin {
        if (!msigApprover[a]) revert NotPolicyAdmin();
        if (msigRequired) {
            if (msigApproverCount <= msigThreshold) revert InvalidRoles();
            _msigRequireAndClear(TAG_REMOVE_APPROVER, keccak256(abi.encodePacked(a)), true);
        }
        msigApprover[a] = false;
        unchecked { msigApproverCount -= 1; }
        if (msigApproverCount > 0 && msigThreshold > msigApproverCount) {
            msigThreshold = msigApproverCount;
            emit MsigThresholdSet(msigThreshold);
        }
        emit MsigApproverRemoved(a);
    }

    function setMsigThreshold(uint8 k) external onlyPolicyAdmin {
        if (k == 0 || k > msigApproverCount) revert InvalidRoles(); // minimal guard
        if (msigRequired) {
            if (k < 2) revert InvalidRoles();
            _msigRequireAndClear(TAG_SET_THRESHOLD, keccak256(abi.encodePacked(k)), true);
        }
        msigThreshold = k;
        emit MsigThresholdSet(k);
    }

    // ---------- Multisig: approval + gate for createPolicy ----------
    function _paramsCreatePolicy(uint8 fromRole, uint8 toRole, uint8 ops, bytes32 schema)
        internal pure returns (bytes32)
    {
        return keccak256(abi.encodePacked(fromRole, toRole, ops, schema));
    }

    function approveCreatePolicy(uint8 fromRole, uint8 toRole, uint8 ops, bytes32 schema) public {
        _msigApprove(TAG_CREATE_POLICY, _paramsCreatePolicy(fromRole, toRole, ops, schema));
    }

    function approvePolicy(uint8 fromRole, uint8 toRole, uint8 ops, bytes32 schema) external {
        approveCreatePolicy(fromRole, toRole, ops, schema);
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
        _msigRequireAndClear(TAG_CREATE_POLICY, _paramsCreatePolicy(uint8(fromRole), uint8(toRole), opsAllowed, ctxSchema), false);

        if (fromRole == NodeType.Unknown || toRole == NodeType.Unknown) revert InvalidRoles();
        if (opsAllowed == 0) revert EmptyOpsAllowed();

        // compute canonical hash and reject duplicates
        bytes32 h = _computePolicyHash(fromRole, toRole, opsAllowed, ctxSchema);
        uint256 existing = policyIdByHash[h];
        if (existing != 0 && !policies[existing].isDeprecated) revert DuplicatePolicy();

        unchecked { policyId = ++nextPolicyId; }

        policies[policyId].fromRole     = fromRole;
        policies[policyId].toRole       = toRole;
        policies[policyId].opsAllowed   = opsAllowed;
        policies[policyId].isDeprecated = false;
        policies[policyId].ctxSchema    = ctxSchema;
        policies[policyId].policyHash   = h;
        policies[policyId].version      = 1;

        // index it for fast duplicate checks
        policyIdByHash[h] = policyId;

        emit PolicyCreated(policyId, fromRole, toRole, opsAllowed, ctxSchema, 1, h);
        emit PolicyChanged(policyId, 1);
    }

    function _paramsUpdatePolicy(uint256 policyId, uint8 opsAllowed, bytes32 ctxSchema) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(policyId, opsAllowed, ctxSchema));
    }

    function approveUpdatePolicy(uint256 policyId, uint8 opsAllowed, bytes32 ctxSchema) external {
        _msigApprove(TAG_UPDATE_POLICY, _paramsUpdatePolicy(policyId, opsAllowed, ctxSchema));
    }

    function updatePolicy(uint256 policyId, uint8 opsAllowed, bytes32 ctxSchema) external onlyPolicyAdmin {
        if (policies[policyId].version == 0) revert PolicyNotFound();
        if (policies[policyId].isDeprecated) revert PolicyIsDeprecated();
        if (opsAllowed == 0) revert EmptyOpsAllowed();

        // Widening (granting an op the policy didn't already allow) is the
        // one thing a lone admin must not be able to do unilaterally --
        // narrowing (a subset of the current ops) stays admin-only, since
        // that only ever restricts, matching "admin can only subtract."
        if ((opsAllowed & ~policies[policyId].opsAllowed) != 0) {
            _msigRequireAndClear(TAG_UPDATE_POLICY, _paramsUpdatePolicy(policyId, opsAllowed, ctxSchema), false);
        }

        // compute new hash and check it doesn't collide with another live policy
        bytes32 newH = _computePolicyHash(policies[policyId].fromRole, policies[policyId].toRole, opsAllowed, ctxSchema);
        uint256 existing = policyIdByHash[newH];
        if (existing != 0 && existing != policyId && !policies[existing].isDeprecated) revert DuplicatePolicy();

        // clear old index and set new
        policyIdByHash[policies[policyId].policyHash] = 0;

        policies[policyId].opsAllowed = opsAllowed;
        policies[policyId].ctxSchema  = ctxSchema;
        unchecked { policies[policyId].version += 1; }
        policies[policyId].policyHash = newH;

        policyIdByHash[newH] = policyId;

        emit PolicyUpdated(policyId, policies[policyId].version, policies[policyId].opsAllowed, policies[policyId].ctxSchema, newH);
        emit PolicyChanged(policyId, policies[policyId].version);
    }

    function deprecatePolicy(uint256 policyId) external onlyPolicyAdmin {
        if (policies[policyId].version == 0) revert PolicyNotFound();
        if (policies[policyId].isDeprecated) revert PolicyIsDeprecated();
        policies[policyId].isDeprecated = true;

        // free the hash so an identical policy can be recreated later if needed
        policyIdByHash[policies[policyId].policyHash] = 0;

        emit PolicyDeprecated(policyId);
        emit PolicyDeprecatedEvent(policyId);
        emit PolicyChanged(policyId, policies[policyId].version);
    }

    function getPolicy(uint256 policyId) external view returns (Policy memory) {
        return policies[policyId];
    }

    // =========================================================
    //                 GRANTS (RESOURCE-OWNER ONLY)
    // =========================================================
    function _grantKey(
        string memory fromNodeSignature,
        string memory toNodeSignature,
        uint256 policyId
    ) internal pure returns (bytes32) {
        // abi.encode with tuple to avoid collisions; includes policyId
        return keccak256(abi.encode(fromNodeSignature, toNodeSignature, policyId));
    }

    function _syncGrantIndex(bytes32 grantId) internal {
        CapabilityGrant storage src = grants[grantId];
        CapabilityGrant storage dst = grantsByTokenId[grantId];
        dst.issuedAt = src.issuedAt;
        dst.expiresAt = src.expiresAt;
        dst.policyId = src.policyId;
        dst.opsSubset = src.opsSubset;
        dst.isIssued = src.isIssued;
        dst.isRevoked = src.isRevoked;
        dst.delegationAllowed = src.delegationAllowed;
        dst.delegationDepth = src.delegationDepth;
        dst.parentGrantId = src.parentGrantId;
        dst.depthDel = src.depthDel;
        dst.parentTokenId = src.parentTokenId;
        dst.generation = src.generation;
        dst.parentGeneration = src.parentGeneration;
    }

    function issueGrant(
        string calldata fromNodeSignature,
        string calldata toNodeSignature,
        uint256 policyId,
        uint8 opsSubset,
        uint64 expiresAt
    ) external {
        _issueGrantCore(fromNodeSignature, toNodeSignature, policyId, opsSubset, expiresAt, false, 0);
    }

    function issueGrant(
        string calldata fromNodeSignature,
        string calldata toNodeSignature,
        uint256 policyId,
        uint8 opsSubset,
        uint64 expiresAt,
        uint8 maxDelegationDepth
    ) external {
        _issueGrantCore(
            fromNodeSignature,
            toNodeSignature,
            policyId,
            opsSubset,
            expiresAt,
            maxDelegationDepth > 0,
            maxDelegationDepth
        );
    }

    function issueGrantDelegable(
        string calldata fromNodeSignature,
        string calldata toNodeSignature,
        uint256 policyId,
        uint8 opsSubset,
        uint64 expiresAt,
        bool delegationAllowed,
        uint8 delegationDepth
    ) external {
        _issueGrantCore(fromNodeSignature, toNodeSignature, policyId, opsSubset, expiresAt, delegationAllowed, delegationDepth);
    }

    function issueToken(
        string calldata fromNodeSignature,
        string calldata toNodeSignature,
        uint256 policyId,
        uint8 opsSubset,
        uint64 expiresAt,
        uint8 maxDelegationDepth
    ) external {
        _issueGrantCore(
            fromNodeSignature,
            toNodeSignature,
            policyId,
            opsSubset,
            expiresAt,
            maxDelegationDepth > 0,
            maxDelegationDepth
        );
    }

    function _issueGrantCore(
        string calldata fromNodeSignature,
        string calldata toNodeSignature,
        uint256 policyId,
        uint8 opsSubset,
        uint64 expiresAt,
        bool delegationAllowed,
        uint8 delegationDepth
    ) internal {
        string memory fromNodeId = nodeSignatureToNodeId[fromNodeSignature];
        string memory toNodeId   = nodeSignatureToNodeId[toNodeSignature];

        if (!iotNodes[fromNodeId].isRegistered || !iotNodes[toNodeId].isRegistered) revert NodeNotRegistered();
        if (msg.sender != iotNodes[toNodeId].registeredBy) revert NotResourceOwner();

        Policy storage p = policies[policyId];
        if (p.version == 0) revert PolicyNotFound();
        if (p.isDeprecated) revert PolicyIsDeprecated();
        if (p.fromRole != iotNodes[fromNodeId].nodeType || p.toRole != iotNodes[toNodeId].nodeType) revert PolicyRoleMismatch();

        if (opsSubset == 0) revert EmptyOpsSubset();
        if ((opsSubset & ~p.opsAllowed) != 0) revert OpsSubsetExceedsAllowed();
        if (expiresAt <= uint64(block.timestamp)) revert InvalidExpiry();

        bytes32 grantId = _grantKey(fromNodeSignature, toNodeSignature, policyId);
        CapabilityGrant storage g = grants[grantId];

        // If there is an active grant for this exact tuple, allow a safe EXTEND/ADJUST instead of rejecting
        bool active = (g.isIssued && !g.isRevoked && uint64(block.timestamp) <= g.expiresAt);
        if (active) {
            // Live attenuation: an active grant can only lose permissions.
            // A delegated child is never widened through its resource owner.
            if ((opsSubset & ~g.opsSubset) != 0) revert OpsSubsetExceedsAllowed();
            g.opsSubset = opsSubset;
            // extend: only allow moving forward, and never beyond a delegated
            // grant's own parent (Assumption 2 / Property 2: the expiry
            // ceiling is retained across re-issuance, not reset).
            if (g.parentTokenId != bytes32(0) && expiresAt > grants[g.parentTokenId].expiresAt) {
                revert InvalidExpiry();
            }
            if (expiresAt > g.expiresAt) {
                g.expiresAt = expiresAt;
            }
            // Remaining delegation depth may not be increased on re-issuance
            // (Assumption 2); lowering it is allowed.
            if (delegationDepth > g.delegationDepth) revert InvalidDelegationDepth();
            g.delegationAllowed = delegationAllowed;
            g.delegationDepth = delegationDepth;
            g.depthDel = delegationDepth;
            // g.parentGrantId / g.parentTokenId are intentionally left
            // untouched here: a still-valid delegated grant retains its
            // parent reference, expiry ceiling, and depth bound across
            // re-issuance (Property 2). Only a lapsed grant, which takes the
            // fresh-issue branch below, becomes a new root grant.
            _syncGrantIndex(grantId);
            emit GrantExtended(grantId, g.expiresAt, g.opsSubset);
            return;
        }

        // fresh issue -- this slot was either never issued, revoked, or
        // expired, so this is a new lineage: bump its generation so any
        // descendant delegated from a PRIOR occupant of this slot fails
        // the ancestor-generation check below rather than silently
        // validating against this new, unrelated grant.
        unchecked { g.generation += 1; }
        g.policyId          = uint32(policyId);
        g.opsSubset         = opsSubset;
        g.issuedAt          = uint64(block.timestamp);
        g.expiresAt         = expiresAt;
        g.isIssued          = true;
        g.isRevoked         = false;
        g.delegationAllowed = delegationAllowed;
        g.delegationDepth   = delegationDepth;
        g.parentGrantId     = bytes32(0);
        g.depthDel          = delegationDepth;
        g.parentTokenId     = bytes32(0);
        g.parentGeneration  = 0;
        _syncGrantIndex(grantId);

        emit GrantIssued(grantId);
    }

    function delegateGrant(
        string calldata currentFromNodeSignature,  // holder of the parent grant
        string calldata toNodeSignature,
        string calldata newFromNodeSignature,      // child "from"
        uint256 policyId,
        uint8 opsSubset,
        uint64 expiresAt
    ) external {
        uint8 parentDepth = grants[_grantKey(currentFromNodeSignature, toNodeSignature, policyId)].depthDel;
        _delegateGrantCore(
            currentFromNodeSignature,
            toNodeSignature,
            newFromNodeSignature,
            policyId,
            opsSubset,
            expiresAt,
            parentDepth > 0 ? parentDepth - 1 : 0
        );
    }

    function issueTokenDelegable(
        string calldata currentFromNodeSignature,
        string calldata toNodeSignature,
        string calldata newFromNodeSignature,
        uint256 policyId,
        uint8 opsSubset,
        uint64 expiresAt,
        uint8 requestedDepth
    ) external {
        _delegateGrantCore(
            currentFromNodeSignature,
            toNodeSignature,
            newFromNodeSignature,
            policyId,
            opsSubset,
            expiresAt,
            requestedDepth
        );
    }

    function _delegateGrantCore(
        string calldata currentFromNodeSignature,
        string calldata toNodeSignature,
        string calldata newFromNodeSignature,
        uint256 policyId,
        uint8 opsSubset,
        uint64 expiresAt,
        uint8 requestedDepth
    ) internal {
        bytes32 parentId = _grantKey(currentFromNodeSignature, toNodeSignature, policyId);
        CapabilityGrant storage parent = grants[parentId];
        if (!parent.isIssued || parent.isRevoked || uint64(block.timestamp) > parent.expiresAt) revert NotGrantHolder();
        if (!parent.delegationAllowed || parent.depthDel == 0) revert InvalidDelegationDepth();

        // Holder-ownership check: caller must control the currentFrom node
        string memory holderNodeId = nodeSignatureToNodeId[currentFromNodeSignature];
        if (msg.sender != iotNodes[holderNodeId].registeredBy) revert NotGrantHolder();

        // Policy must be live, and the child must not exceed policy or parent
        Policy storage p = policies[parent.policyId];
        if (p.version == 0) revert PolicyNotFound();
        if (p.isDeprecated) revert PolicyIsDeprecated();
        if (opsSubset == 0) revert EmptyOpsSubset();
        if ((opsSubset & ~p.opsAllowed) != 0) revert OpsSubsetExceedsAllowed();
        if ((opsSubset & ~parent.opsSubset) != 0) revert OpsSubsetExceedsAllowed();
        if (expiresAt <= uint64(block.timestamp) || expiresAt > parent.expiresAt) revert InvalidExpiry();
        if (requestedDepth >= parent.depthDel || parent.depthDel == 0) revert InvalidDelegationDepth();

        // Create/extend child grant (newFrom -> to, same policyId)
        bytes32 childId = _grantKey(newFromNodeSignature, toNodeSignature, policyId);
        CapabilityGrant storage c = grants[childId];

        // If active, allow safe adjust/extend under the same constraints
        if (c.isIssued && !c.isRevoked && uint64(block.timestamp) <= c.expiresAt) {
            // An active lineage is immutable in parent and may only narrow.
            if (c.parentTokenId != parentId) revert NotGrantHolder();
            if ((opsSubset & ~c.opsSubset) != 0) revert OpsSubsetExceedsAllowed();
            if (requestedDepth > c.depthDel) revert InvalidDelegationDepth();
            c.opsSubset = opsSubset;
            if (expiresAt > c.expiresAt) {
                c.expiresAt = expiresAt;
            }
            c.delegationAllowed = requestedDepth > 0;
            c.delegationDepth = requestedDepth;
            c.depthDel = requestedDepth;
            c.parentGrantId = parentId;
            c.parentTokenId = parentId;
            // This is an explicit, holder-authorized re-delegation call
            // (not an automatic re-issue path), so it is the correct place
            // to refresh which parent generation this child is pinned to,
            // in case the parent slot was revoked and explicitly re-granted
            // to the same holder since this child was first delegated.
            c.parentGeneration = parent.generation;
            _syncGrantIndex(childId);
            // keep link/flags if already set
            emit GrantExtended(childId, c.expiresAt, c.opsSubset);
            return;
        }

        // Fresh child grant; propagate delegation flags and depth. This
        // child's own slot was inactive, so it is a new lineage at this
        // slot too -- bump its own generation for the same reason as
        // _issueGrantCore's fresh-issue branch.
        unchecked { c.generation += 1; }
        c.policyId          = uint32(parent.policyId);
        c.opsSubset         = opsSubset;
        c.issuedAt          = uint64(block.timestamp);
        c.expiresAt         = expiresAt;
        c.isIssued          = true;
        c.isRevoked         = false;
        c.delegationAllowed = requestedDepth > 0;
        c.delegationDepth   = requestedDepth;
        c.depthDel          = requestedDepth;
        c.parentGrantId     = parentId;
        c.parentTokenId     = parentId;
        c.parentGeneration  = parent.generation;
        _syncGrantIndex(childId);

        emit GrantDelegated(parentId, childId, c.delegationDepth);
    }
    function _revokeGrantCore(string calldata fromNodeSignature, string calldata toNodeSignature, uint256 policyId) internal {
        bytes32 grantId = _grantKey(fromNodeSignature, toNodeSignature, policyId);
        string memory toNodeId = nodeSignatureToNodeId[toNodeSignature];
        if (msg.sender != iotNodes[toNodeId].registeredBy) revert NotResourceOwner();
        if (!grants[grantId].isIssued) revert PolicyNotFound();
        if (grants[grantId].isRevoked) revert AlreadyRevoked();

        grants[grantId].isRevoked = true;
        grantsByTokenId[grantId].isRevoked = true;
        emit GrantRevoked(grantId);
    }

    function revokeGrant(string calldata fromNodeSignature, string calldata toNodeSignature, uint256 policyId) external {
        _revokeGrantCore(fromNodeSignature, toNodeSignature, policyId);
    }

    function revokeToken(string calldata fromNodeSignature, string calldata toNodeSignature, uint256 policyId) external {
        _revokeGrantCore(fromNodeSignature, toNodeSignature, policyId);
    }

    // getGrant (a strict subset of getGrantEx's fields) was removed here to
    // reclaim deploy-size headroom (R07): confirmed unused by the actual
    // daemon (Node_root/orchestrator.py calls getGrantEx exclusively);
    // getGrantEx remains available for the same lookup with more fields.

    function getGrantEx(
        string calldata fromNodeSignature,
        string calldata toNodeSignature,
        uint256 policyId
    )
        external
        view
        returns (
            uint256 policyIdOut,
            uint8 opsSubset,
            uint64 issuedAt,
            uint64 expiresAt,
            bool isIssued,
            bool isRevoked,
            bool delegationAllowed,
            uint8 delegationDepth
        )
    {
        bytes32 id = _grantKey(fromNodeSignature, toNodeSignature, policyId);
        CapabilityGrant storage g = grants[id];
        return (g.policyId, g.opsSubset, g.issuedAt, g.expiresAt, g.isIssued, g.isRevoked, g.delegationAllowed, g.delegationDepth);
    }

    function getGrantLineage(
        string calldata fromNodeSignature,
        string calldata toNodeSignature,
        uint256 policyId
    ) external view returns (uint8 depthDelOut, bytes32 parentTokenIdOut) {
        bytes32 id = _grantKey(fromNodeSignature, toNodeSignature, policyId);
        CapabilityGrant storage g = grants[id];
        return (g.depthDel, g.parentTokenId);
    }

    function _evaluateGrant(
        string calldata fromNodeSignature,
        string calldata toNodeSignature,
        uint256 policyId,
        uint8 opBit
    ) private view returns (bool, string memory) {
        bytes32 grantId = _grantKey(fromNodeSignature, toNodeSignature, policyId);
        CapabilityGrant storage g = grants[grantId];
        if (!g.isIssued) return (false, "not_issued");
        if (g.isRevoked) return (false, "revoked");
        if (uint64(block.timestamp) > g.expiresAt) return (false, "expired");

        bytes32 ancestorId = g.parentTokenId;
        uint32 expectedGeneration = g.parentGeneration;
        for (uint8 depth = 0; depth < 10 && ancestorId != bytes32(0); depth++) {
            CapabilityGrant storage parent = grantsByTokenId[ancestorId];
            if (!parent.isIssued) return (false, "parent_not_issued");
            if (parent.isRevoked) return (false, "parent_revoked");
            if (uint64(block.timestamp) > parent.expiresAt) return (false, "parent_expired");
            // Root-soundness fix: a (from,to,policyId) triple is a fixed,
            // reusable storage slot. If this ancestor slot was revoked and
            // later re-granted to an unrelated purpose, its generation
            // moved past what this descendant recorded at delegation time
            // -- fail rather than silently validating against the new,
            // unrelated occupant of the same slot.
            if (parent.generation != expectedGeneration) return (false, "parent_generation_mismatch");
            // A descendant is evaluated against live ancestor attenuation,
            // not merely the policy that existed at delegation time.
            if ((parent.opsSubset & opBit) == 0) return (false, "parent_op_missing");
            ancestorId = parent.parentTokenId;
            expectedGeneration = parent.parentGeneration;
        }
        if (ancestorId != bytes32(0)) return (false, "parent_depth_exceeded");

        Policy storage p = policies[g.policyId];
        if (p.version == 0) return (false, "policy_not_found");
        if (p.isDeprecated) return (false, "policy_deprecated");

        if ((g.opsSubset & opBit) == 0) return (false, "grant_op_missing");
        if ((p.opsAllowed & opBit) == 0) return (false, "policy_op_missing");

        return (true, "granted");
    }

    function checkGrant(
        string calldata fromNodeSignature,
        string calldata toNodeSignature,
        uint256 policyId,
        uint8 opBit
    ) external view returns (bool) {
        (bool ok, ) = _evaluateGrant(fromNodeSignature, toNodeSignature, policyId, opBit);
        return ok;
    }

    function checkGrantAndLog(
        string calldata fromNodeSignature,
        string calldata toNodeSignature,
        uint256 policyId,
        uint8 opBit
    ) external returns (bool) {
        (bool ok, string memory reason) = _evaluateGrant(fromNodeSignature, toNodeSignature, policyId, opBit);
        string memory fromNodeId = nodeSignatureToNodeId[fromNodeSignature];
        string memory toNodeId = nodeSignatureToNodeId[toNodeSignature];
        address fromAddr = iotNodes[fromNodeId].registeredBy;
        address toAddr = iotNodes[toNodeId].registeredBy;
        bytes32 policyKey = bytes32(policyId);

        if (ok) {
            emit AccessGranted(fromAddr, toAddr, policyKey, opBit, block.timestamp);
        } else {
            emit AccessDenied(fromAddr, toAddr, policyKey, opBit, reason, block.timestamp);
        }
        return ok;
    }

    function isGrantExpired(
        string calldata fromNodeSignature,
        string calldata toNodeSignature,
        uint256 policyId
    )
        external
        view
        returns (bool)
    {
        bytes32 grantId = _grantKey(fromNodeSignature, toNodeSignature, policyId);
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
        ) revert NodeNotRegistered();

        // Consensus membership is maintained by QBFT, outside this contract;
        // an on-chain role record must not be treated as that membership.
        return false;
    }
}
