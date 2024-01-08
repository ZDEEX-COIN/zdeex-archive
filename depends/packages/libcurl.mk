package=libcurl

ifeq ($(host_os),mingw32)
$(package)_version=7.67.0
$(package)_file_name=curl-$($(package)_version).tar.gz
$(package)_sha256_hash=52af3361cf806330b88b4fe6f483b6844209d47ae196ac46da4de59bb361ab02
else
$(package)_version=8.4.0
$(package)_file_name=curl-$($(package)_version).tar.gz
$(package)_sha256_hash=816e41809c043ff285e8c0f06a75a1fa250211bbfb2dc0a037eeef39f1a9e427
endif

$(package)_dependencies=wolfssl
$(package)_download_path=https://curl.haxx.se/download
$(package)_config_opts_linux=--disable-shared --enable-static --without-ssl --prefix=$(host_prefix) --host=$(host)
$(package)_config_opts_mingw32=--enable-mingw --disable-shared --enable-static --with-wolfssl --without-ssl --prefix=$(host_prefix) --host=x86_64-w64-mingw32
$(package)_config_opts_darwin=--disable-shared --enable-static --without-ssl --prefix=$(host_prefix)
$(package)_cflags_darwin=-mmacosx-version-min=10.9
$(package)_conf_tool=./configure

ifeq ($(build_os),darwin)
define $(package)_set_vars
  $(package)_build_env=MACOSX_DEPLOYMENT_TARGET="10.9"
endef
endif

ifeq ($(build_os),linux)
define $(package)_set_vars
  $(package)_config_env=LD_LIBRARY_PATH="$(host_prefix)/lib" PKG_CONFIG_LIBDIR="$(host_prefix)/lib/pkgconfig" CPPFLAGS="-I$(host_prefix)/include" LDFLAGS="-L$(host_prefix)/lib"
endef
endif


define $(package)_config_cmds
  echo '=== config for $(package):' && \
  echo '$($(package)_config_env) $($(package)_conf_tool) $($(package)_config_opts)' && \
  echo '=== ' && \
  $($(package)_config_env) $($(package)_conf_tool) $($(package)_config_opts) 
endef

ifeq ($(build_os),darwin)
define $(package)_build_cmds
  $(MAKE) CPPFLAGS="-I$(host_prefix)/include -fPIC" CFLAGS='-mmacosx-version-min=10.9'
endef
else
define $(package)_build_cmds
  $(MAKE)
endef
endif

define $(package)_stage_cmds
  echo 'Staging dir: $($(package)_staging_dir)$(host_prefix)/' && \
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef
