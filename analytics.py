"""Clearly labelled illustrative data for the Mid-II analytics page.
Replace this sample with verified package scan records before reporting results."""
import pandas as pd

SAMPLE_ROWS = [
    {"package": "sample-a", "dependency_count": 2, "vulnerability_count": 0, "suspicious_api_count": 0, "risk_score": 5, "risk_level": "Low"},
    {"package": "sample-b", "dependency_count": 5, "vulnerability_count": 1, "suspicious_api_count": 1, "risk_score": 30, "risk_level": "Medium"},
    {"package": "sample-c", "dependency_count": 8, "vulnerability_count": 2, "suspicious_api_count": 0, "risk_score": 50, "risk_level": "High"},
    {"package": "sample-d", "dependency_count": 12, "vulnerability_count": 4, "suspicious_api_count": 3, "risk_score": 85, "risk_level": "Critical"},
    {"package": "sample-e", "dependency_count": 3, "vulnerability_count": 0, "suspicious_api_count": 0, "risk_score": 10, "risk_level": "Low"},
    {"package": "sample-f", "dependency_count": 9, "vulnerability_count": 3, "suspicious_api_count": 2, "risk_score": 75, "risk_level": "Critical"},
    {"package": "sample-g", "dependency_count": 4, "vulnerability_count": 1, "suspicious_api_count": 0, "risk_score": 25, "risk_level": "Medium"},
    {"package": "sample-h", "dependency_count": 7, "vulnerability_count": 2, "suspicious_api_count": 1, "risk_score": 55, "risk_level": "High"},
    {"package": "sample-i", "dependency_count": 6, "vulnerability_count": 0, "suspicious_api_count": 1, "risk_score": 20, "risk_level": "Medium"},
    {"package": "sample-j", "dependency_count": 10, "vulnerability_count": 3, "suspicious_api_count": 2, "risk_score": 70, "risk_level": "Critical"},
]


def get_demo_analytics():
    df = pd.DataFrame(SAMPLE_ROWS)
    numeric = ["dependency_count", "vulnerability_count", "suspicious_api_count", "risk_score"]
    descriptive = {}
    central = {}
    for col in numeric:
        s = df[col]
        modes = s.mode().tolist()
        descriptive[col] = {
            "count": int(s.count()),
            "min": float(s.min()),
            "max": float(s.max()),
            "mean": round(float(s.mean()), 2),
            "std": round(float(s.std(ddof=1)), 2),
            "q1": round(float(s.quantile(.25)), 2),
            "median": round(float(s.median()), 2),
            "q3": round(float(s.quantile(.75)), 2),
        }
        central[col] = {
            "mean": round(float(s.mean()), 2),
            "median": round(float(s.median()), 2),
            "mode": modes if modes else []
        }

    corr = df[numeric].corr().round(3)
    # One-way ANOVA example compares risk_score between groups. It is illustrative only;
    # scores were manually authored for this demo, so do not use as project evidence.
    groups = [group["risk_score"].values for _, group in df.groupby("risk_level") if len(group) >= 2]
    anova = {"f_statistic": None, "p_value": None, "note": "Not calculated: sample data is illustrative and groups are not validated."}
    try:
        from scipy.stats import f_oneway
        if len(groups) >= 2:
            f_stat, p_val = f_oneway(*groups)
            anova = {"f_statistic": round(float(f_stat), 4), "p_value": round(float(p_val), 6),
                     "note": "Illustrative result only; do not present as measured project performance."}
    except Exception:
        pass

    return {
        "label": "ILLUSTRATIVE DEMO DATA — NOT REAL SCAN RESULTS",
        "rows": SAMPLE_ROWS,
        "descriptive": descriptive,
        "central_tendency": central,
        "correlation": {"columns": numeric, "matrix": corr.values.tolist()},
        "risk_distribution": df["risk_level"].value_counts().to_dict(),
        "anova": anova
    }
