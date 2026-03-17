import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import hashlib


# ── FM Algorithm ──────────────────────────────────────────────────────────────

def count_trailing_zeros(x):
    """Return the number of trailing zero bits (position of lowest set bit)."""
    if x == 0:
        return 0
    return (x & -x).bit_length() - 1


def fm_estimate(stream, num_hashes=100):
    """Estimate distinct count of `stream` using Flajolet-Martin sketches."""
    estimates = []
    for seed in range(num_hashes):
        max_zeros = 0
        for ip in stream:
            hash_value = int(
                hashlib.md5((ip + str(seed)).encode("utf-8")).hexdigest(), 16
            )
            tz = count_trailing_zeros(hash_value)
            if tz > max_zeros:
                max_zeros = tz
        phi = 0.77351
        estimates.append((2 ** max_zeros) / phi)
    return np.median(estimates)


# ── Sliding Window ────────────────────────────────────────────────────────────

def sliding_window_fm(df, window_size, step, num_hashes=100):
    """
    Run FM estimation over sliding windows of `df`.
    Expects a 'Source' column containing IP addresses.
    """
    results = []
    for start in range(0, len(df) - window_size + 1, step):
        window = df.iloc[start : start + window_size]
        source_ips = window["Source"].tolist()
        fm_est = fm_estimate(source_ips, num_hashes)
        actual_distinct = len(set(source_ips))
        error = (
            abs(fm_est - actual_distinct) / actual_distinct
            if actual_distinct > 0
            else 0
        )
        results.append(
            {
                "window_start": start,
                "window_end": start + window_size,
                "fm_estimate": fm_est,
                "actual_distinct": actual_distinct,
                "relative_error": error,
            }
        )
    return pd.DataFrame(results)


# ── Streamlit UI ──────────────────────────────────────────────────────────────

st.title("StreamShield: Network IDS")

uploaded_file = st.file_uploader("Upload your Network Traffic CSV", type="csv")

if uploaded_file:
    df = pd.read_csv(uploaded_file,encoding='utf-8', encoding_errors='ignore')

    # ── NULL handling ──────────────────────────────────────────────────────────
    null_counts = df.isnull().sum()
    if null_counts.any():
        st.warning(f"⚠️ NULL values detected:\n{null_counts[null_counts > 0].to_dict()}")

    # BUG FIX: use .index to get the actual index labels, not the sub-DataFrame
    null_rows = df[df["Protocol"].isnull()]
    if null_rows.empty:
        st.success("✅ No NULL values found in provided dataset column.")
    else:
        st.warning(f"⚠️ Dropping {len(null_rows)} row(s) with NULL 'Protocol'.")
        df = df.drop(index=null_rows.index).reset_index(drop=True)

    # ── Sliding window analysis ────────────────────────────────────────────────
    window_size = 500
    step = 250
    num_hashes = 100

    # BUG FIX: single call; pass only the columns the function needs
    results_df = sliding_window_fm(df[["Source"]], window_size, step, num_hashes)

    # ── Anomaly detection ──────────────────────────────────────────────────────
    baseline = results_df["actual_distinct"].median()
    results_df["suspicious"] = results_df["fm_estimate"] > (1.5 * baseline)

    mean_relative_error = results_df["relative_error"].mean()

    # ── Display results ────────────────────────────────────────────────────────
    st.subheader("Sliding Window Analysis")
    st.dataframe(results_df)

    st.metric("Mean Relative Error (FM vs Actual)", f"{mean_relative_error:.3f}")

    # Chart: FM estimate vs actual distinct count
    fig, ax = plt.subplots(figsize=(10, 4))
    ax.plot(results_df["window_start"], results_df["actual_distinct"],
            label="Actual Distinct", linewidth=2)
    ax.plot(results_df["window_start"], results_df["fm_estimate"],
            label="FM Estimate", linestyle="--", linewidth=2)
    ax.axhline(1.5 * baseline, color="red", linestyle=":", label="Anomaly Threshold")
    ax.set_xlabel("Window Start Index")
    ax.set_ylabel("Distinct Source IPs")
    ax.set_title("FM Estimate vs Actual Distinct Source IPs")
    ax.legend()
    st.pyplot(fig)

    # ── Verdict ────────────────────────────────────────────────────────────────
    if results_df["suspicious"].any():
        st.error("🚨 MALICIOUS ACTIVITY DETECTED!")
        st.subheader("Suspicious Windows")
        st.dataframe(results_df[results_df["suspicious"]])
    else:
        st.success("✅ NETWORK TRAFFIC SECURE")