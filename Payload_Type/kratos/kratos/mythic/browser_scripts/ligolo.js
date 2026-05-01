function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    } else if(responses.length === 0){
        return {'plaintext': "No response yet from agent..."};
    }

    const raw = responses[responses.length - 1];

    if(!raw.trimStart().startsWith("[")){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    }

    let sessions = [];
    try {
        sessions = JSON.parse(raw);
    } catch(e) {
        return {'plaintext': raw};
    }

    if(sessions.length === 0){
        return {'plaintext': "No active ligolo sessions."};
    }

    const headers = [
        {"plaintext": "actions", "type": "button", "width": 100, "disableSort": true, "cellStyle": {}},
        {"plaintext": "pid",     "type": "number", "width": 80,  "copyIcon": true, "cellStyle": {}},
        {"plaintext": "status",  "type": "string", "width": 100, "cellStyle": {}},
        {"plaintext": "connect", "type": "string", "fillWidth": true, "copyIcon": true, "cellStyle": {}},
        {"plaintext": "path",    "type": "string", "fillWidth": true, "copyIcon": true, "cellStyle": {}},
    ];

    const rows = sessions.map(function(s){
        const isRunning = s["status"] === "running";
        const rowStyle = isRunning
            ? {backgroundColor: "rgba(0,200,100,0.15)"}
            : {backgroundColor: "rgba(200,50,50,0.15)"};

        return {
            "rowStyle": rowStyle,
            "pid":     {"plaintext": s["pid"],     "cellStyle": {}, "copyIcon": true},
            "status":  {"plaintext": s["status"],  "cellStyle": {color: isRunning ? "limegreen" : "tomato"}},
            "connect": {"plaintext": s["connect"], "cellStyle": {}, "copyIcon": true},
            "path":    {"plaintext": s["path"],    "cellStyle": {}, "copyIcon": true},
            "actions": {"button": {
                "name": "Actions",
                "type": "menu",
                "value": [
                    {
                        "name": "Stop session",
                        "type": "task",
                        "ui_feature": "ligolo:stop",
                        "parameters": JSON.stringify({"pid": s["pid"]})
                    },
                    {
                        "name": "Copy connect string",
                        "type": "dictionary",
                        "value": {
                            "Connect": s["connect"],
                            "PID":     String(s["pid"]),
                            "Path":    s["path"]
                        },
                        "leftColumnTitle": "Field",
                        "rightColumnTitle": "Value",
                        "title": "Session details"
                    }
                ]
            }}
        };
    });

    return {"table": [{"headers": headers, "rows": rows, "title": "Ligolo-ng Sessions"}]};
}
