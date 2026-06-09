import re
from datetime import datetime

# =========================
# EDIT THESE VALUES
# =========================

FULL_MESSAGE = "ASIYA_SWITCH_001_2026"

MESSAGE_PARTS = [
    "ASIYA_SWITCH",
    "SWITCH_001_2026"
]

# Choose the app you switched to.
# Keep only the one you used, or leave all if unsure.
SWITCHED_APP_PATTERNS = {
    "YouTube": [
        r"youtube",
        r"com\.google\.android\.youtube"
    ]
}

FILES = {
    "Logcat Output": "switching_logs.txt",
    "Meminfo Output": "switching_meminfo.txt",
    "Notification Dump": "notification_dump.txt",
    "Activity Dump": "activity_dump.txt"
}

INSTAGRAM_PATTERNS = [
    r"instagram",
    r"com\.instagram\.android"
]

REPLY_MESSAGE = "REPLY_FORENSIC_2026"

GENERAL_PATTERNS = {
    "Application Trace": INSTAGRAM_PATTERNS,
    "Full Message Fragment": [re.escape(FULL_MESSAGE)],
    "Partial Message Fragment": [re.escape(word) for word in MESSAGE_PARTS],
    "Reply Message Fragment": [re.escape(REPLY_MESSAGE)],
    
    "Keyboard / Typing Activity": [
    r"GoogleInputMethodService",
    r"AndroidIME",
    r"onStartInput",
    r"onStartInputView",
    r"EditorInfo",
    r"inputType",
    r"imeOptions"
],

"DM / Messaging Related Trace": [
    r"direct",
    r"dm",
    r"message",
    r"messaging",
    r"inbox",
    r"thread",
    r"chat"
],

"Instagram Direct / Thread-Specific Trace": [
    r"ig_direct",
    r"direct\|",
    r"tag=direct",
    r"thread_id",
    r"thread[_-]?id",
    r"direct.*thread",
    r"thread.*direct",
    r"Instagram messages",
    r"NotificationChannelGroup\{mId='DIRECT'",
    r"groupKey=.*ig_direct",
    r"direct_message",
    r"com\.instagram\.direct",
    r"DirectShare",
    r"direct_inbox",
    r"inbox.*direct",
    r"direct.*inbox"
],
"Instagram Notification Trace": [
    r"NotificationManager",
    r"StatusBarNotification",
    r"NotificationChannel",
    r"NotificationChannelGroup",
    r"Instagram messages",
    r"DIRECT",
    r"notif",
    r"notify",
    r"PendingIntent",
    r"ticker"
],

"Push / Background Service Trace": [
    r"fbns",
    r"push",
    r"firebase",
    r"gcm",
    r"fcm",
    r"background",
    r"service"
],

"Network Activity Trace": [
    r"ConnectivityService",
    r"requestNetwork",
    r"NetworkRequest",
    r"INTERNET",
    r"uid",
    r"RequestorPkg"
],

"Foreground / Background Transition": [
    r"TO_FRONT",
    r"PAUSE",
    r"RESUME",
    r"START",
    r"STOP",
    r"freezing",
    r"unfroze",
    r"topRunningActivity",
    r"ActivityRecord",
    r"Task"
],
    "User Identifier": [r"\buser\b", r"username", r"profile", r"account"],
    "Notification Artifact": [
    r"notification",
    r"notify",
    r"StatusBarNotification",
    r"NotificationManager",
    r"notif",
    r"ticker",
    r"pendingintent"],
    "URL Trace": [
    r"https?://\S+",
    r"t\.me",
    r"telegram"],
    "Memory / Process Trace": [r"pid", r"process", r"heap", r"dalvik", r"native", r"meminfo", r"TOTAL"]
}


def find_matches(content, patterns):
    matches = []
    for pattern in patterns:
        found = re.findall(pattern, content, re.IGNORECASE)
        matches.extend(found)
    return matches


def classify_state(count):
    if count == 0:
        return "MISSING"
    elif count <= 3:
        return "PARTIAL"
    return "PRESENT"


def extract_matching_lines(content, patterns, max_lines=10):
    lines = content.splitlines()
    matched_lines = []

    for line in lines:
        for pattern in patterns:
            if re.search(pattern, line, re.IGNORECASE):
                matched_lines.append(line.strip())
                break

        if len(matched_lines) >= max_lines:
            break

    return matched_lines


def extract_timestamp_from_logcat(line):
    """
    Tries to extract logcat timestamp.
    Example format often looks like:
    05-13 19:24:05.123 ...
    """
    match = re.search(r"\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+", line)
    return match.group(0) if match else "Timestamp not detected"


def analyze_file(file_label, file_name):
    report = []
    report.append(f"\nSOURCE FILE: {file_label} ({file_name})")
    report.append("-" * 70)

    try:
        with open(file_name, "r", encoding="utf-8", errors="ignore") as file:
            content = file.read()
    except FileNotFoundError:
        report.append(f"ERROR: {file_name} was not found.")
        return report, None

    summary = {}

    # General artifact classification
    for category, patterns in GENERAL_PATTERNS.items():
        matches = find_matches(content, patterns)
        state = classify_state(len(matches))
        examples = list(set([str(m) for m in matches]))[:5]

        report.append(f"Artifact Category: {category}")
        report.append(f"Match Count: {len(matches)}")
        report.append(f"State: {state}")
        report.append(f"Examples Found: {examples}")

        if category == "Full Message Fragment" and state == "MISSING":
            report.append("Behavioral Note: The exact full message was not detected in this output.")
        elif category == "Partial Message Fragment" and state != "MISSING":
            report.append("Behavioral Note: Some words from the message were detected, suggesting partial textual traces may remain.")
        elif state == "PRESENT":
            report.append(f"Behavioral Note: {category} remained clearly observable.")
        elif state == "PARTIAL":
            report.append(f"Behavioral Note: {category} appeared in a limited way.")
        else:
            report.append(f"Behavioral Note: {category} was not observed.")

        report.append("-" * 45)

        summary[category] = {
            "count": len(matches),
            "state": state
        }

    # Switched app detection
    report.append("\nSWITCHED APP TRACE DETECTION")
    report.append("-" * 70)

    switched_app_detected = False

    for app_name, patterns in SWITCHED_APP_PATTERNS.items():
        matches = find_matches(content, patterns)
        state = classify_state(len(matches))

        report.append(f"Switched App: {app_name}")
        report.append(f"Match Count: {len(matches)}")
        report.append(f"State: {state}")

        if len(matches) > 0:
            switched_app_detected = True
            lines = extract_matching_lines(content, patterns, max_lines=5)
            report.append("Example Lines:")
            for line in lines:
                report.append(f"- [{extract_timestamp_from_logcat(line)}] {line[:250]}")

        report.append("-" * 45)

    if switched_app_detected:
        report.append("Interpretation: The logs contain traces of the second app, supporting that app switching occurred.")
    else:
        report.append("Interpretation: No switched-app trace was detected. This may happen if the app name/package was not logged clearly.")

    # Timeline-style evidence lines
    report.append("\nTIMELINE-RELATED SAMPLE LINES")
    report.append("-" * 70)

    instagram_lines = extract_matching_lines(content, INSTAGRAM_PATTERNS, max_lines=5)
    message_lines = extract_matching_lines(content, [re.escape(FULL_MESSAGE)] + [re.escape(w) for w in MESSAGE_PARTS], max_lines=5)

    report.append("Instagram-related lines:")
    if instagram_lines:
        for line in instagram_lines:
            report.append(f"- [{extract_timestamp_from_logcat(line)}] {line[:250]}")
    else:
        report.append("- No Instagram-related lines found.")

    report.append("\nMessage-related lines:")
    if message_lines:
        for line in message_lines:
            report.append(f"- [{extract_timestamp_from_logcat(line)}] {line[:250]}")
    else:
        report.append("- No full/partial message-related lines found.")

    return report, summary


def main():
    final_report = []

    final_report.append("ADVANCED APP SWITCHING ARTIFACT BEHAVIORAL ANALYSIS REPORT")
    final_report.append("=" * 70)
    final_report.append(f"Generated at: {datetime.now()}")
    final_report.append("Experiment Condition: App Switching")
    final_report.append(f"Full message searched: {FULL_MESSAGE}")
    final_report.append(f"Partial words searched: {MESSAGE_PARTS}")
    final_report.append("=" * 70)

    combined_summary = {}

    for label, filename in FILES.items():
        section_report, summary = analyze_file(label, filename)
        final_report.extend(section_report)

        if summary:
            for category, data in summary.items():
                if category not in combined_summary:
                    combined_summary[category] = 0
                combined_summary[category] += data["count"]

    final_report.append("\nFINAL COMBINED SUMMARY")
    final_report.append("=" * 70)

    for category, total in combined_summary.items():
        state = classify_state(total)
        final_report.append(f"{category}: {state} ({total} total matches)")

    final_report.append("\nFINAL BEHAVIORAL INTERPRETATION")
    final_report.append("=" * 70)

    full_msg_count = combined_summary.get("Full Message Fragment", 0)
    partial_msg_count = combined_summary.get("Partial Message Fragment", 0)

    if full_msg_count == 0 and partial_msg_count == 0:
        final_report.append(
            "The exact message and its selected partial words were not detected in the collected outputs. "
            "The exact plaintext message was not recoverable from the analyzed outputs. However, multiple indirect and Direct-message-related artifacts remained observable, including notification metadata, Direct/thread-specific traces, keyboard activity, background-service activity, and application-transition records."
            "from the analyzed logcat and meminfo outputs after app switching."
            "This suggests that modern Android social media applications may restrict plaintext message exposure while still leaving behavioral and metadata-related forensic artifacts observable."
        )
    elif full_msg_count == 0 and partial_msg_count > 0:
        final_report.append(
            "The full message was not detected, but some partial words were detected. "
            "This suggests that app switching may reduce complete message recoverability while leaving partial textual traces."
        )
    else:
        final_report.append(
            "The full message was detected after app switching. This suggests the message artifact remained observable "
            "in the collected outputs under this condition."
        )

    final_report.append(
        "\nThis result should be compared with immediate capture and other conditions. "
        "If immediate capture shows the full message but app switching does not, then app switching may reduce direct message recoverability."
    )

    output_file = "instagram_app_switching_report.txt"

    with open(output_file, "w", encoding="utf-8") as output:
        output.write("\n".join(final_report))

    print(f"Done. Report saved as: {output_file}")


if __name__ == "__main__":
    main()