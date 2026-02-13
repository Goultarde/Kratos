SRC = main.c Checkin.c utils.c \
      command_shell.c command_run.c command_getuid.c command_pwd.c command_cd.c command_ls.c command_sleep.c command_exit.c

kratos: $(SRC)
	$(CC) $(CFLAGS) -o kratos.exe $(SRC) -lwinhttp

clean:
	rm -f kratos.exe
