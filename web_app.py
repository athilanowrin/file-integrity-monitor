from flask import Flask, render_template, jsonify
import os
import hashlib
import json
from datetime import datetime
from sklearn.ensemble import IsolationForest

app = Flask(__name__)

MONITORED_FOLDER = "monitored_files"
BASELINE_FILE = "baseline.json"

AI_FOLDER = "ai"
HISTORY_FILE = os.path.join(AI_FOLDER, "activity_history.json")
STATE_FILE = os.path.join(AI_FOLDER, "ai_state.json")

os.makedirs(AI_FOLDER, exist_ok=True)


# =========================================================
# FILE HASHING
# =========================================================

def calculate_hash(file_path):
    sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as file:
            while True:
                data = file.read(4096)

                if not data:
                    break

                sha256.update(data)

        return sha256.hexdigest()

    except (PermissionError, OSError):
        return None


# =========================================================
# SCAN MONITORED FILES
# =========================================================

def scan_files():

    file_hashes = {}

    for root, _, files in os.walk(MONITORED_FOLDER):

        for filename in files:

            file_path = os.path.join(root, filename)

            file_hash = calculate_hash(file_path)

            if file_hash:
                file_hashes[file_path] = file_hash

    return file_hashes


# =========================================================
# LOAD BASELINE
# =========================================================

def load_baseline():

    if not os.path.exists(BASELINE_FILE):
        return None

    try:

        with open(BASELINE_FILE, "r") as file:
            return json.load(file)

    except (json.JSONDecodeError, OSError):

        return None


# =========================================================
# AI HISTORY
# =========================================================

def load_history():

    if not os.path.exists(HISTORY_FILE):
        return []

    try:

        with open(HISTORY_FILE, "r") as file:
            return json.load(file)

    except (json.JSONDecodeError, OSError):

        return []


def save_history(history):

    with open(HISTORY_FILE, "w") as file:

        json.dump(history, file, indent=4)


# =========================================================
# AI STATE
# =========================================================

def load_ai_state():

    if not os.path.exists(STATE_FILE):

        return {
            "last_activity": None,
            "result": "LEARNING",
            "message": "AI is collecting normal activity data.",
            "score": None
        }

    try:

        with open(STATE_FILE, "r") as file:
            return json.load(file)

    except (json.JSONDecodeError, OSError):

        return {
            "last_activity": None,
            "result": "LEARNING",
            "message": "AI is collecting normal activity data.",
            "score": None
        }


def save_ai_state(state):

    with open(STATE_FILE, "w") as file:

        json.dump(state, file, indent=4)


# =========================================================
# AI + SECURITY ANALYSIS
# =========================================================

def analyze_activity(new_count, modified_count, deleted_count):

    history = load_history()

    current_activity = [
        new_count,
        modified_count,
        deleted_count
    ]

    # -----------------------------------------------------
    # Avoid analysing the exact same activity repeatedly
    # -----------------------------------------------------

    state = load_ai_state()

    if state.get("last_activity") == current_activity:

        return state


    # -----------------------------------------------------
    # Save activity history
    # -----------------------------------------------------

    history.append({

        "timestamp": datetime.now().isoformat(),

        "new": new_count,

        "modified": modified_count,

        "deleted": deleted_count

    })

    save_history(history)


    # =====================================================
    # SECURITY RULES
    # =====================================================

    # Any deleted file is considered suspicious.
    # This gives the FIM an immediate security response.

    if deleted_count > 0:

        state = {

            "last_activity": current_activity,

            "result": "ANOMALY",

            "message": (
                "File deletion detected. "
                "The monitored file set has been altered."
            ),

            "score": -1.0

        }

        save_ai_state(state)

        return state


    # Multiple modifications are suspicious.

    if modified_count >= 2:

        state = {

            "last_activity": current_activity,

            "result": "ANOMALY",

            "message": (
                "Multiple file modifications detected. "
                "The activity pattern requires investigation."
            ),

            "score": -0.8

        }

        save_ai_state(state)

        return state


    # Multiple new files are suspicious.

    if new_count >= 3:

        state = {

            "last_activity": current_activity,

            "result": "ANOMALY",

            "message": (
                "Multiple new files detected. "
                "Unusual file creation activity was observed."
            ),

            "score": -0.7

        }

        save_ai_state(state)

        return state


    # =====================================================
    # AI LEARNING
    # =====================================================

    if len(history) < 5:

        state = {

            "last_activity": current_activity,

            "result": "LEARNING",

            "message": (
                "AI is collecting normal activity data."
            ),

            "score": None

        }

        save_ai_state(state)

        return state


    # -----------------------------------------------------
    # Prepare historical training data
    # -----------------------------------------------------

    training_data = []

    for item in history[:-1]:

        training_data.append([

            item["new"],

            item["modified"],

            item["deleted"]

        ])


    # Need enough variation for meaningful analysis

    if len(training_data) < 4:

        state = {

            "last_activity": current_activity,

            "result": "LEARNING",

            "message": (
                "AI is learning normal file activity patterns."
            ),

            "score": None

        }

        save_ai_state(state)

        return state


    # =====================================================
    # ISOLATION FOREST
    # =====================================================

    model = IsolationForest(

        contamination="auto",

        random_state=42,

        n_estimators=100

    )

    model.fit(training_data)


    prediction = model.predict([
        current_activity
    ])[0]


    score = model.decision_function([
        current_activity
    ])[0]


    # =====================================================
    # AI RESULT
    # =====================================================

    if prediction == -1:

        result = "ANOMALY"

        message = (

            "Unusual file activity detected. "

            "The current activity pattern differs "

            "from normal historical behaviour."

        )

    else:

        result = "NORMAL"

        message = (

            "File activity matches the normal "

            "historical behaviour."

        )


    state = {

        "last_activity": current_activity,

        "result": result,

        "message": message,

        "score": round(float(score), 4)

    }

    save_ai_state(state)

    return state


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/")
def home():

    return render_template("index.html")


# =========================================================
# API STATUS
# =========================================================

@app.route("/api/status")
def status():

    baseline = load_baseline()

    if baseline is None:

        return jsonify({

            "status": "No baseline",

            "new": [],

            "modified": [],

            "deleted": [],

            "ai_result": "NO BASELINE",

            "ai_message": "Create a baseline first.",

            "ai_score": None

        })


    old_files = baseline.get("files", {})

    current_files = scan_files()


    new_files = []

    modified_files = []

    deleted_files = []


    # =====================================================
    # NEW + MODIFIED FILES
    # =====================================================

    for file_path, current_hash in current_files.items():

        if file_path not in old_files:

            new_files.append(file_path)

        elif old_files[file_path] != current_hash:

            modified_files.append(file_path)


    # =====================================================
    # DELETED FILES
    # =====================================================

    for file_path in old_files:

        if file_path not in current_files:

            deleted_files.append(file_path)


    # =====================================================
    # COUNTS
    # =====================================================

    new_count = len(new_files)

    modified_count = len(modified_files)

    deleted_count = len(deleted_files)


    # =====================================================
    # AI ANALYSIS
    # =====================================================

    if (
        new_count == 0
        and modified_count == 0
        and deleted_count == 0
    ):

        ai_state = load_ai_state()

        ai_result = "NORMAL"

        ai_message = (
            "No new file activity detected. "
            "System is monitoring normally."
        )

        ai_score = ai_state.get("score")

    else:

        ai_state = analyze_activity(

            new_count,

            modified_count,

            deleted_count

        )

        ai_result = ai_state["result"]

        ai_message = ai_state["message"]

        ai_score = ai_state["score"]


    # =====================================================
    # RESPONSE
    # =====================================================

    return jsonify({

        "status": "Integrity check completed",

        "new": new_files,

        "modified": modified_files,

        "deleted": deleted_files,

        "ai_result": ai_result,

        "ai_message": ai_message,

        "ai_score": ai_score

    })


# =========================================================
# RUN SERVER
# =========================================================

if __name__ == "__main__":

    app.run(debug=True)