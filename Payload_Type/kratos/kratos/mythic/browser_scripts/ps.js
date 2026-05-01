function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce((prev, cur) => prev + cur, "");
        return {'plaintext': combined};
    } else if(responses.length > 0){
        let data = [];
        let rows = [];
        let headers = [
            {"plaintext": "actions",  "type": "button", "cellStyle": {}, "width": 100, "disableSort": true},
            {"plaintext": "ppid",     "type": "number", "copyIcon": true, "cellStyle": {}, "width": 80},
            {"plaintext": "pid",      "type": "number", "copyIcon": true, "cellStyle": {}, "width": 80},
            {"plaintext": "arch",     "type": "string", "cellStyle": {}, "width": 60},
            {"plaintext": "name",     "type": "string", "cellStyle": {}, "fillWidth": true},
            {"plaintext": "user",     "type": "string", "cellStyle": {}, "fillWidth": true},
            {"plaintext": "path",     "type": "string", "cellStyle": {}, "fillWidth": true},
        ];

        try {
            data = JSON.parse(responses[0]);
        } catch(error) {
            const combined = responses.reduce((prev, cur) => prev + cur, "");
            return {'plaintext': combined};
        }

        let avProcesses = ["MsMpEng","MsSense","CSFalconService","CSFalconContainer","CylanceSvc",
            "CylanceUI","ekrn","egui","avp","avguard","AvastSvc","AvastUI","mbamservice","mbamtray",
            "bdagent","bdss","bdlite","xagt","xagtnotif","cb","redcloak","OmniAgent","CrAmTray","AmSvc"];
        let adminTools = ["cmd","powershell","taskmgr","regedit","regedit32","procexp","procexp64",
            "Procmon","PsExec","PsExec64","wireshark","putty","MobaXterm","bash","git-bash",
            "notepad","notepad++","Code","windbg","x64dbg","ida64","idag","idaw"];

        for(let j = 0; j < data.length; j++){
            let p = data[j];
            let rowStyle = {};
            let name = p["name"] || "";
            let baseName = name.replace(/\.exe$/i, "");

            if(p["is_agent"]){
                rowStyle = {backgroundColor: "gold", color: "black"};
            } else if(avProcesses.some(av => baseName.toLowerCase() === av.toLowerCase())){
                rowStyle = {backgroundColor: "indianred", color: "black"};
            } else if(adminTools.some(t => baseName.toLowerCase() === t.toLowerCase())){
                rowStyle = {backgroundColor: "rgb(106,255,255)", color: "black"};
            } else if(baseName === "explorer" || baseName === "winlogon"){
                rowStyle = {backgroundColor: "cornflowerblue", color: "black"};
            }

            let row = {
                "rowStyle": rowStyle,
                "ppid":    {"plaintext": p["parent_process_id"], "cellStyle": {}, "copyIcon": true},
                "pid":     {"plaintext": p["process_id"],        "cellStyle": {}, "copyIcon": true},
                "arch":    {"plaintext": p["architecture"],      "cellStyle": {}},
                "name":    {"plaintext": p["name"],              "cellStyle": {}},
                "user":    {"plaintext": p["user"],              "cellStyle": {}},
                "path":    {"plaintext": p["bin_path"],          "cellStyle": {}},
                "actions": {"button": {
                    "name": "Actions",
                    "type": "menu",
                    "value": [
                        {
                            "name": "More Info",
                            "type": "dictionary",
                            "value": {
                                "Process Path": p["bin_path"],
                                "Host":         p["host"]
                            },
                            "leftColumnTitle": "Attribute",
                            "rightColumnTitle": "Value",
                            "title": "Info — " + p["name"]
                        },
                        {
                            "name": "Steal Token",
                            "type": "task",
                            "ui_feature": "steal_token",
                            "parameters": p["process_id"]
                        },
                        {
                            "name": "Kill",
                            "type": "task",
                            "startIcon": "kill",
                            "ui_feature": "kill",
                            "parameters": p["process_id"]
                        }
                    ]
                }},
            };
            rows.push(row);
        }

        return {"table": [{"headers": headers, "rows": rows}]};
    } else {
        return {"plaintext": "No response yet from agent..."};
    }
}
