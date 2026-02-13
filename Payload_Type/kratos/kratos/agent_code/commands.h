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

#endif // KRATOS_COMMANDS_H
