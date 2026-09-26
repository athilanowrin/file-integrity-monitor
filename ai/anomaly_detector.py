import json
import os
from datetime import datetime

from sklearn.ensemble import IsolationForest


HISTORY_FILE = "ai/activity_history.json"


def load_history():
    """Load previous file activity data."""
    if not os.path.exists(HISTORY_FILE):
        return []

    try:
        with open(HISTORY_FILE, "r") as file:
            return json.load(file)
    except (json.JSONDecodeError, OSError):
        return []


def save_history(history):
    """Save activity history."""
    os.makedirs("ai", exist_ok=True)

    with open(HISTORY_FILE, "w") as file:
        json.dump(history, file, indent=4)


def analyze_activity(new_files, modified_files, deleted_files):
    """
    Analyze FIM activity using Isolation Forest.

    Returns:
        NORMAL or ANOMALY
    """

    history = load_history()

    current_activity = [
        new_files,
        modified_files,
        deleted_files
    ]

    # Store current activity
    history.append({
        "timestamp": datetime.now().isoformat(),
        "new": new_files,
        "modified": modified_files,
        "deleted": deleted_files
    })

    save_history(history)

    # Need enough historical data for meaningful AI analysis
    if len(history) < 5:
        return {
            "result": "LEARNING",
            "message": "AI is collecting normal activity data.",
            "score": None
        }

    # Prepare training data
    training_data = [
        [
            item["new"],
            item["modified"],
            item["deleted"]
        ]
        for item in history[:-1]
    ]

    model = IsolationForest(
        contamination="auto",
        random_state=42
    )

    model.fit(training_data)

    prediction = model.predict([current_activity])[0]
    score = model.decision_function([current_activity])[0]

    if prediction == -1:
        result = "ANOMALY"
        message = "Suspicious file activity detected."
    else:
        result = "NORMAL"
        message = "File activity appears normal."

    return {
        "result": result,
        "message": message,
        "score": round(float(score), 4)
    }


if __name__ == "__main__":

    print("=== AI File Activity Anomaly Detector ===")

    result = analyze_activity(
        new_files=0,
        modified_files=1,
        deleted_files=0
    )

    print("\nAI Result:", result["result"])
    print("Message:", result["message"])

    if result["score"] is not None:
        print("Anomaly Score:", result["score"])