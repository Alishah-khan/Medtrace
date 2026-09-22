// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// MedTrace audit contract.
/// Stores only hashes and IDs. Raw sensor data stays off-chain.
contract MedTrace {
    address public admin;

    struct Anchor {
        bytes32 root;      // Merkle root of a batch of record hashes
        uint32 fromSeq;    // first record number in the batch
        uint32 toSeq;      // last record number in the batch
        uint64 anchoredAt; // block timestamp
    }

    struct Handover {
        bytes32 sender;       // salted hash of sender card UID
        bytes32 receiver;     // salted hash of receiver card UID
        bytes32 snapshotHash; // hash of the signed handover record
        uint64 ts;            // device time of the handover
        uint64 recordedAt;    // block timestamp
    }

    mapping(bytes32 => bytes) private boxKeys;
    mapping(bytes32 => bool) public boxRegistered;
    mapping(bytes32 => bool) public isHandler;
    mapping(bytes32 => Anchor[]) private anchors;
    mapping(bytes32 => Handover[]) private handovers;

    event BoxRegistered(bytes32 indexed boxId);
    event HandlerRegistered(bytes32 indexed cardHash);
    event BatchAnchored(bytes32 indexed boxId, bytes32 root, uint32 fromSeq, uint32 toSeq);
    event HandoverRecorded(bytes32 indexed boxId, bytes32 sender, bytes32 receiver, bytes32 snapshotHash, uint64 ts);
    event ExcursionFlagged(bytes32 indexed boxId, uint32 seq, uint8 kind);

    modifier onlyAdmin() {
        require(msg.sender == admin, "not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerBox(bytes32 boxId, bytes calldata pubKey) external onlyAdmin {
        require(!boxRegistered[boxId], "box exists");
        boxRegistered[boxId] = true;
        boxKeys[boxId] = pubKey;
        emit BoxRegistered(boxId);
    }

    function getBoxKey(bytes32 boxId) external view returns (bytes memory) {
        return boxKeys[boxId];
    }

    function registerHandler(bytes32 cardHash) external onlyAdmin {
        isHandler[cardHash] = true;
        emit HandlerRegistered(cardHash);
    }

    function anchorBatch(bytes32 boxId, bytes32 root, uint32 fromSeq, uint32 toSeq) external onlyAdmin {
        require(boxRegistered[boxId], "unknown box");
        require(toSeq >= fromSeq, "bad range");
        Anchor[] storage list = anchors[boxId];
        if (list.length > 0) {
            require(fromSeq == list[list.length - 1].toSeq + 1, "range not contiguous");
        }
        list.push(Anchor(root, fromSeq, toSeq, uint64(block.timestamp)));
        emit BatchAnchored(boxId, root, fromSeq, toSeq);
    }

    function recordHandover(
        bytes32 boxId,
        bytes32 senderHash,
        bytes32 receiverHash,
        bytes32 snapshotHash,
        uint64 ts
    ) external onlyAdmin {
        require(boxRegistered[boxId], "unknown box");
        require(isHandler[senderHash] && isHandler[receiverHash], "handler not authorized");
        handovers[boxId].push(Handover(senderHash, receiverHash, snapshotHash, ts, uint64(block.timestamp)));
        emit HandoverRecorded(boxId, senderHash, receiverHash, snapshotHash, ts);
    }

    function flagExcursion(bytes32 boxId, uint32 seq, uint8 kind) external onlyAdmin {
        require(boxRegistered[boxId], "unknown box");
        emit ExcursionFlagged(boxId, seq, kind);
    }

    function anchorCount(bytes32 boxId) external view returns (uint256) {
        return anchors[boxId].length;
    }

    function getAnchor(bytes32 boxId, uint256 i)
        external
        view
        returns (bytes32 root, uint32 fromSeq, uint32 toSeq, uint64 anchoredAt)
    {
        Anchor storage a = anchors[boxId][i];
        return (a.root, a.fromSeq, a.toSeq, a.anchoredAt);
    }

    function handoverCount(bytes32 boxId) external view returns (uint256) {
        return handovers[boxId].length;
    }

    function getHandover(bytes32 boxId, uint256 i)
        external
        view
        returns (bytes32 sender, bytes32 receiver, bytes32 snapshotHash, uint64 ts, uint64 recordedAt)
    {
        Handover storage h = handovers[boxId][i];
        return (h.sender, h.receiver, h.snapshotHash, h.ts, h.recordedAt);
    }
}
