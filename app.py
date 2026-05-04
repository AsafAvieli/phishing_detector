"""
Streamlit web UI — paste or upload raw email content and display phishing analysis.

Run with: streamlit run app.py
Requires the FastAPI backend to be running on port 8000.
"""

from __future__ import annotations

import requests
import streamlit as st

API_URL = "http://127.0.0.1:8000"
ANALYZE_URL = f"{API_URL.rstrip('/')}/analyze"


def _inject_product_css() -> None:
    """Strip Streamlit's default chrome (menu, footer, deploy button, sidebar)
    so the page looks like a standalone product rather than a Streamlit demo.
    """
    st.markdown(
        """
        <style>
            header[data-testid="stHeader"] { display: none !important; }
            div[data-testid="stToolbar"] { display: none !important; }
            #MainMenu { visibility: hidden !important; }
            div[data-testid="stDeployButton"],
            button[kind="header"],
            .stDeployButton { display: none !important; }
            footer { visibility: hidden !important; height: 0 !important; }
            div[data-testid="stBottomBlockContainer"] { display: none !important; }
            section[data-testid="stSidebar"],
            div[data-testid="collapsedControl"] { display: none !important; }
            div[data-testid="stAppViewContainer"] > .main {
                margin-left: 0 !important;
                max-width: 100% !important;
            }
            .block-container { padding-top: 1.5rem !important; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _display_analysis_results(
    is_phishing: bool,
    risk: int,
    indicators: list[str],
) -> None:
    """Render the verdict banner, metric cards, progress bar, and indicator list."""
    if is_phishing:
        st.error("**High risk:** This message matches phishing heuristics.")
    else:
        st.success("**Lower risk:** Score is below the phishing threshold.")

    m1, m2, m3 = st.columns(3)
    with m1:
        st.metric("Phishing verdict", "Yes" if is_phishing else "No")
    with m2:
        st.metric("Risk score", f"{risk} / 100")
    with m3:
        st.metric("Indicators found", len(indicators))

    st.progress(min(100, max(0, risk)) / 100.0)

    st.subheader("Detected indicators")
    if indicators:
        for item in indicators:
            st.warning(item)
    else:
        st.write("No heuristic indicators triggered.")


def _run_analysis(raw_text: str) -> None:
    """POST the raw email to the FastAPI backend and store the result in session state.

    Results are stored in session_state rather than returned directly so they
    persist across Streamlit reruns (which happen on every widget interaction).
    """
    with st.spinner("Analyzing email…"):
        try:
            resp = requests.post(
                ANALYZE_URL,
                json={"raw_email": raw_text},
                timeout=60,
            )
        except requests.RequestException as e:
            st.error(f"Request failed: {e}")
            return

    if not resp.ok:
        st.error(f"API error HTTP {resp.status_code}: {resp.text}")
        return

    data = resp.json()
    st.session_state["last_analysis"] = {
        "is_phishing": data.get("is_phishing", False),
        "risk": int(data.get("risk_score", 0)),
        "indicators": data.get("detected_indicators") or [],
    }


def main() -> None:
    st.set_page_config(
        page_title="Phishing Email Detector",
        page_icon="🛡️",
        layout="wide",
    )

    _inject_product_css()

    st.title("Phishing Email Detector")
    st.markdown(
        "Paste raw email source or upload a `.txt` / `.eml` file for instant heuristic analysis."
    )

    tab_paste, tab_upload = st.tabs(["Paste Content", "Upload File"])

    with tab_paste:
        pasted = st.text_area(
            "Email content",
            height=280,
            placeholder=(
                "Paste the full raw email here (headers and body), as exported from your mail client "
                "or saved from a `.eml` file."
            ),
            label_visibility="collapsed",
        )
        st.caption("Paste the complete message, including headers, for the most accurate results.")
        if st.button("Analyze Email", type="primary", key="analyze_paste"):
            if not pasted or not pasted.strip():
                st.warning("Please paste raw email content before analyzing.")
            else:
                _run_analysis(pasted)

    with tab_upload:
        uploaded = st.file_uploader(
            "Email file",
            type=["txt", "eml"],
            help="Exported `.eml` or a `.txt` containing raw MIME.",
            label_visibility="collapsed",
        )
        st.caption("Upload a `.eml` export or a text file containing the raw email.")
        if st.button("Analyze Email", type="primary", key="analyze_upload"):
            if uploaded is None:
                st.warning("Please choose a file to analyze.")
            else:
                raw_bytes = uploaded.getvalue()
                try:
                    raw_text = raw_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    # Older .eml files are often encoded in latin-1 rather than UTF-8.
                    raw_text = raw_bytes.decode("latin-1", errors="replace")
                _run_analysis(raw_text)

    # Display the most recent result (persists until a new analysis runs).
    last = st.session_state.get("last_analysis")
    if last is not None:
        _display_analysis_results(last["is_phishing"], last["risk"], last["indicators"])


if __name__ == "__main__":
    main()
