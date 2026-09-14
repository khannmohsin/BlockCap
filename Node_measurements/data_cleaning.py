import argparse
import os
import sys
import pandas as pd
from datetime import datetime

NODE_ROOT = "/Users/khannmohsin/VSCode_Projects/MyDisIoT_Project/Node_measurements/trial_1"

# --- Fix (see measurement_script_trace.md / section_vic_corrections.md): ---
# This script used to open every output file in append mode unconditionally
# (mode='a' whenever the file already existed), so re-running it against an
# already-processed function_metrics.csv silently duplicated every matched
# block on the second run, shifting every downstream mean. The integrity
# check in the remediation pass found no evidence this had already happened
# to the checked-in trial_1/ data (no duplicate blank-line blocks, no exact
# duplicate rows), but the bug itself was real and is fixed here:
#   - each output file is truncated (not appended to) the first time this
#     run writes to it; only writes *within* the same run for the same file
#     (multiple matches of the same sequence) still append, as intended.
#   - the script refuses to run at all, without --force, if any target
#     output file already contains data, so a second run cannot silently
#     clobber or duplicate a first run's results.
_WRITTEN_THIS_RUN = set()


def _guard_against_existing_output(force: bool) -> None:
    if force:
        return
    existing = []
    for node in os.listdir(NODE_ROOT) if os.path.isdir(NODE_ROOT) else []:
        node_path = os.path.join(NODE_ROOT, node, "measurements")
        if not os.path.isdir(node_path):
            continue
        for file_name, _ in SEQUENCES:
            candidate = os.path.join(node_path, file_name)
            if os.path.exists(candidate) and os.path.getsize(candidate) > 0:
                existing.append(candidate)
    if existing:
        print(
            "Refusing to run: the following output files already contain data "
            "and this script cannot tell whether it has already been run "
            "against the current function_metrics.csv (re-running would risk "
            "duplicating blocks). Remove/back up these files first, or pass "
            "--force to overwrite them:\n  " + "\n  ".join(existing),
            file=sys.stderr,
        )
        sys.exit(1)

SEQUENCES = [
    ("validator_registration.csv", [
        "check_smart_contract", "check_smart_contract_deployment",
        "verify_node_identity", "is_node_registered_js", "register_node_on_chain",
        "get_enode", "send_acknowledgment", "get_peers*", "emitValidatorProposalToChain", "proposeValidator"
    ]),
    ("non-validator_registration.csv", [
        "check_smart_contract", "check_smart_contract_deployment",
        "verify_node_identity", "is_node_registered_js", "register_node_on_chain",
        "get_enode", "send_acknowledgment"
    ]),
    ("token_issuance.csv", [
        "check_smart_contract", "check_smart_contract_deployment",
        "is_node_registered_js", "get_node_details_js", "check_token_availability",
        "issue_capability_token", "get_capability_token"
    ]),
    ("already_issued_token.csv", [
        "check_smart_contract", "check_smart_contract_deployment",
        "is_node_registered_js", "get_node_details_js", "check_token_availability",
        "check_token_expiry", "get_capability_token"
    ]),
    ("already_registered_check.csv", [
        "check_smart_contract", "check_smart_contract_deployment",
        "verify_node_identity", "is_node_registered_js"
    ]),
    ("initialization.csv", [
        "generate_account", "create_qbft_file", "generate_keys",
        "create_genesis_file", "update_genesis_file", "update_extra_data_in_genesis"
    ]),
    ("initialization_client.csv", ["generate_keys"]),
    ("reg_request.csv", ["load_public_key", "get_address", "sign_identity", "register_node"]),
    ("acc_request.csv", ["load_public_key", "get_address", "sign_identity", "read_data"]),
    ("acc_request.csv", ["load_public_key", "get_address", "sign_identity", "write_data"]),
    ("acc_request.csv", ["load_public_key", "get_address", "sign_identity", "update_data"]),
    ("acc_request.csv", ["load_public_key", "get_address", "sign_identity", "remove_data"]),
]

def parse_timestamp(ts):
    try:
        return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
    except Exception:
        return pd.NaT

def find_sequence_with_get_peers_star(df, sequence):
    i = 0
    while i < len(df):
        temp = []
        j = 0
        k = i
        while j < len(sequence) and k < len(df):
            expected = sequence[j]
            actual = df.iloc[k]["function"]
            if expected == "get_peers*":
                while k < len(df) and df.iloc[k]["function"] == "get_peers":
                    temp.append(k)
                    k += 1
                j += 1
            elif expected == actual:
                temp.append(k)
                j += 1
                k += 1
            else:
                break
        if j == len(sequence):
            return temp
        i += 1
    return None

_parser = argparse.ArgumentParser(description=__doc__ if "__doc__" in dir() else None)
_parser.add_argument("--force", action="store_true",
                      help="Overwrite existing output files even though this "
                           "script cannot verify they weren't already produced "
                           "by a prior run.")
_args = _parser.parse_args()
_guard_against_existing_output(_args.force)

for node in os.listdir(NODE_ROOT):
    node_path = os.path.join(NODE_ROOT, node, "measurements")
    if not os.path.isdir(node_path):
        continue

    func_file = os.path.join(node_path, "function_metrics.csv")
    if not os.path.exists(func_file):
        continue

    df = pd.read_csv(func_file)
    df["timestamp"] = df["timestamp"].apply(parse_timestamp)
    df = df.dropna(subset=["timestamp"])
    df = df.reset_index(drop=True)

    for file_name, sequence in SEQUENCES:
        while True:
            if "get_peers*" in sequence:
                match = find_sequence_with_get_peers_star(df, sequence)
            else:
                match = []
                seq_idx = 0
                for idx in range(len(df)):
                    if df.iloc[idx]["function"] == sequence[seq_idx]:
                        match.append(idx)
                        seq_idx += 1
                        if seq_idx == len(sequence):
                            break
                    else:
                        match = []
                        seq_idx = 0
                if seq_idx != len(sequence):
                    match = None

            if not match:
                break

            matched_df = df.iloc[match]
            save_path = os.path.join(node_path, file_name)

            # Write matched rows. Truncate (not append) the first time this
            # run touches save_path; append only for further matches of the
            # same sequence within this same run (see fix note above).
            if save_path in _WRITTEN_THIS_RUN:
                matched_df.to_csv(save_path, mode='a', header=False, index=False)
            else:
                matched_df.to_csv(save_path, mode='w', header=True, index=False)
                _WRITTEN_THIS_RUN.add(save_path)

            # Add a blank line to separate sequences
            with open(save_path, 'a') as f:
                f.write('\n')

            df = df.drop(index=matched_df.index).reset_index(drop=True)

    df.to_csv(os.path.join(node_path, "remaining_function_metrics.csv"), index=False)
    print(f"Processed node: {node}")