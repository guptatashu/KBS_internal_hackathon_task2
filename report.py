"""Readable console summary of a scanner result."""


def print_scan_report(r):
    print(f"Scanned {r['scope']['filesScanned']} file(s) with {len(r['rules'])} rules. "
          f"Signals: {r['summary']['bySeverity']}")
    not_triggered = ", ".join(r["summary"]["rulesNotTriggered"]) or "(none)"
    print(f"Not triggered: {not_triggered}\n")

    for f in r["findings"]:
        s = "" if f["count"] == 1 else "s"
        print(f"[{f['severity'].upper()}] {f['rule']} ({f['count']} occurrence{s})")
        for e in f["evidence"]:
            dep = " [dependency]" if e["inDependency"] else ""
            print(f"    {e['file']}:{e['line']}{dep}  {e['snippet']}")
            if e["detail"]:
                print(f"      -> {e['detail']}")
        if f["evidenceTruncated"]:
            print(f"    ... {f['count'] - len(f['evidence'])} more")
    print("\n" + r["disclaimer"])



def _bullets(items, fmt):
    for it in items:
        print("  - " + fmt(it))


def print_analysis(a):
    """Readable console view of an analyzer.analyze_contract result ({"analysis", "meta"})."""
    x, m = a["analysis"], a["meta"]
    print(f"\n=== AI analysis ({m['provider']} / {m['model']}) ===")
    print(f"Risk level: {x['riskLevel']}")
    print(f"Purpose:    {x['contractPurpose']}")
    print(f"\n{x['summary']}\n\nReasoning: {x['riskReasoning']}")

    sections = [
        ("Key functions", x["keyFunctions"], lambda i: f"{i['name']} [{i['visibility']}]: {i['description']}"),
        ("Permissions", x["permissions"], lambda i: f"{i['role']}: {'; '.join(i['capabilities'])}"
                                                    + (f" ({', '.join(i['functions'])})" if i["functions"] else "")),
        ("Fund movement", x["fundMovement"], lambda i: f"{i['function']} - {i['mechanism']}; access: {i['accessControl']}. {i['description']}"),
        ("External calls", x["externalCalls"], lambda i: f"{i['function']} - {i['kind']} -> {i['target']}. {i['description']}"),
        ("Interaction risks", x["interactionRisks"], lambda i: f"{i['description']} (depends on: {i['dependsOn']})"),
    ]
    for title, items, fmt in sections:
        if items:
            print(f"\n{title}:")
            _bullets(items, fmt)

    if x["securityFindings"]:
        print("\nSecurity findings:")
        for f in x["securityFindings"]:
            where = ", ".join(f"{e['file']}:{e['line']}" for e in f["evidence"]) or "scanner evidence"
            rule = f" [scanner: {f['scannerRule']}]" if f["scannerRule"] else ""
            print(f"  [{f['severity']}] {f['title']}{rule}  (confidence {f['confidence']}, {where})")
            print(f"      observed:       {f['observed']}")
            print(f"      potential risk: {f['potentialRisk']}")
    for title, items in (("Recommendations", x["recommendations"]), ("Limitations", x["limitations"])):
        if items:
            print(f"\n{title}:")
            _bullets(items, str)

    notes = list(m["warnings"]) + [f"{d['count']} item(s) dropped in {d['section']}: {d['reason']}" for d in m["dropped"]]
    if m["scannerRulesNotReferenced"] and m["scannerFindingsProvided"]:
        notes.append("Scanner signals the AI did not discuss: " + ", ".join(m["scannerRulesNotReferenced"]))
    if notes:
        print("\nValidation notes:")
        _bullets(notes, str)
    print("\n" + m["disclaimer"])
