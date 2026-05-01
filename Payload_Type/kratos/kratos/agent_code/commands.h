#ifndef KRATOS_COMMANDS_H
#define KRATOS_COMMANDS_H

void command_shell(char *task_id, char *params);
void command_run(char *task_id, char *params);
void command_getuid(char *task_id, char *params);
void command_pwd(char *task_id, char *params);
void command_cd(char *task_id, char *params);
void command_ls(char *task_id, char *params);
void command_sleep(char *task_id, char *params);
void command_exit(char *task_id, char *params);
void command_cat(char *task_id, char *params);
void command_cp(char *task_id, char *params);
void command_mv(char *task_id, char *params);
void command_rm(char *task_id, char *params);
void command_mkdir(char *task_id, char *params);
void command_ps(char *task_id, char *params);
void command_kill(char *task_id, char *params);
void command_whoami(char *task_id, char *params);
void command_ifconfig(char *task_id, char *params);
void command_download(char *task_id, char *params);
void command_upload(char *task_id, char *params);
void command_steal_token(char *task_id, char *params);
void command_make_token(char *task_id, char *params);
void command_runas(char *task_id, char *params);
void command_rev2self(char *task_id, char *params);
void command_socks(char *task_id, char *params);
void command_rportfwd(char *task_id, char *params);
void command_ligolo_start(char *task_id, char *params);
void command_ligolo_stop(char *task_id, char *params);
void command_ligolo_status(char *task_id, char *params);
void command_spawnto(char *task_id, char *params);
void command_spawn(char *task_id, char *params);

#endif // KRATOS_COMMANDS_H
