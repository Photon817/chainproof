// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title BountyEscrow
/// @notice Immunefi-style audit bounty for the local demo chain. A sponsor
///         funds a pool, an auditor submits a report hash plus the PoC
///         transaction hash, and a judge releases the reward. The point is to
///         connect "the agent proved the bug" with "the agent gets paid".
contract BountyEscrow {
    enum Severity {
        None,
        Low,
        Medium,
        High,
        Critical
    }

    enum Status {
        None,
        Submitted,
        Approved,
        Paid,
        Rejected
    }

    struct Report {
        address auditor;
        bytes32 reportHash;
        bytes32 pocTxHash;
        Severity severity;
        Status status;
        uint256 reward;
    }

    address public immutable sponsor;
    address public judge;
    uint256 public immutable maxReward;
    uint256 public pool;

    mapping(bytes32 => Report) private _reports;
    mapping(bytes32 => bool) private _known;

    event PoolFunded(address indexed sponsor, uint256 amount);
    event ReportSubmitted(
        bytes32 indexed reportId,
        address indexed auditor,
        bytes32 reportHash,
        bytes32 pocTxHash,
        Severity severity
    );
    event ReportApproved(bytes32 indexed reportId, uint256 reward);
    event ReportRejected(bytes32 indexed reportId, string reason);
    event RewardPaid(bytes32 indexed reportId, address indexed auditor, uint256 amount);

    error NotJudge();
    error AlreadyExists();
    error UnknownReport();
    error InvalidStatus();
    error SeverityTooLow();
    error RewardTooLarge();
    error TransferFailed();

    modifier onlyJudge() {
        if (msg.sender != judge) revert NotJudge();
        _;
    }

    constructor(address judge_, uint256 maxReward_) payable {
        require(judge_ != address(0), "BountyEscrow: judge required");
        require(maxReward_ > 0, "BountyEscrow: reward required");

        sponsor = msg.sender;
        judge = judge_;
        maxReward = maxReward_;

        if (msg.value > 0) {
            pool = msg.value;
            emit PoolFunded(msg.sender, msg.value);
        }
    }

    function fund() external payable {
        pool += msg.value;
        emit PoolFunded(msg.sender, msg.value);
    }

    /// @notice Called by the audit agent (auditor EOA) with the evidence hashes.
    function submit(bytes32 reportId, bytes32 reportHash, bytes32 pocTxHash, Severity severity) external {
        if (_known[reportId]) revert AlreadyExists();
        if (severity < Severity.High) revert SeverityTooLow();

        _known[reportId] = true;
        _reports[reportId] = Report({
            auditor: msg.sender,
            reportHash: reportHash,
            pocTxHash: pocTxHash,
            severity: severity,
            status: Status.Submitted,
            reward: 0
        });

        emit ReportSubmitted(reportId, msg.sender, reportHash, pocTxHash, severity);
    }

    function approve(bytes32 reportId, uint256 reward) external onlyJudge {
        Report storage report = _reports[reportId];
        if (report.status != Status.Submitted) revert InvalidStatus();
        if (reward == 0 || reward > maxReward || reward > pool) revert RewardTooLarge();

        report.reward = reward;
        report.status = Status.Approved;
        emit ReportApproved(reportId, reward);
    }

    function pay(bytes32 reportId) external onlyJudge {
        Report storage report = _reports[reportId];
        if (report.status != Status.Approved) revert InvalidStatus();

        report.status = Status.Paid;
        pool -= report.reward;

        (bool ok, ) = report.auditor.call{value: report.reward}("");
        if (!ok) revert TransferFailed();

        emit RewardPaid(reportId, report.auditor, report.reward);
    }

    function reject(bytes32 reportId, string calldata reason) external onlyJudge {
        Report storage report = _reports[reportId];
        if (report.status != Status.Submitted) revert InvalidStatus();

        report.status = Status.Rejected;
        emit ReportRejected(reportId, reason);
    }

    function report(bytes32 reportId) external view returns (Report memory) {
        return _reports[reportId];
    }
}
