package=libsodium
$(package)_version=1.0.18
$(package)_download_path=https://git.hush.is/attachments
$(package)_file_name=0d9f589e-a9f9-4ddb-acaa-0f1b423b32eb
$(package)_download_file=0d9f589e-a9f9-4ddb-acaa-0f1b423b32eb
$(package)_sha256_hash=6f504490b342a4f8a4c4a02fc9b866cbef8622d5df4e5452b46be121e46636c1
$(package)_dependencies=
$(package)_config_opts=
ifeq ($(build_os),darwin)
define $(package)_set_vars
  $(package)_build_env=MACOSX_DEPLOYMENT_TARGET="10.11"
  $(package)_cc=clang
  $(package)_cxx=clang++
endef
endif

define $(package)_preprocess_cmds
  cd $($(package)_build_subdir); ./autogen.sh
endef

define $(package)_config_cmds
  $($(package)_autoconf) --enable-static --disable-shared
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef
