package=wolfssl
$(package)_version=4.6.0
$(package)_download_path=https://github.com/wolfSSL/wolfssl/archive
$(package)_download_file=v$($(package)_version)-stable.tar.gz
$(package)_file_name=wolfssl-$($(package)_version).tar.gz
$(package)_sha256_hash=053aefbb02d0b06b27c5e2df6875b4b587318755b7db9d6aa8d72206b310a848

define $(package)_set_vars
$(package)_config_env=AR="$($(package)_ar)" RANLIB="$($(package)_ranlib)" CC="$($(package)_cc)"
$(package)_config_opts=--prefix=$(host_prefix)
$(package)_config_opts+=--host=$(host)
$(package)_config_opts+=--enable-ecc
$(package)_config_opts+=--enable-static
$(package)_config_opts+=--enable-debug
$(package)_config_opts+=--enable-sha3
$(package)_config_opts+=--enable-sha512
$(package)_config_opts+=--enable-tls13

# TODO: enable this in a future version
#$(package)_config_opts+=--enable-xchacha # New in 4.6.0

# TODO: these caused problems
#$(package)_config_opts+=--disable-tlsv12
#$(package)_config_opts+=--disable-oldtls

$(package)_config_opts+=--disable-shared
$(package)_config_opts+=--disable-examples
$(package)_config_opts+=--disable-crypttests
$(package)_config_opts+=--enable-keygen
$(package)_config_opts+=--enable-certgen
$(package)_config_opts+=--enable-bigcache
$(package)_config_opts+=--enable-enckeys
# TODO: can we reduce down to only the normal openssl compat, without these options?
$(package)_config_opts+=--enable-opensslall
$(package)_config_opts+=--enable-opensslextra
$(package)_config_opts+=C_EXTRA_FLAGS="-DSPEAK_AND_TRANSACT_FREELY"

endef

define $(package)_preprocess_cmds
  cd $($(package)_build_subdir); ./autogen.sh
endef

define $(package)_config_cmds
  ./configure $($(package)_config_opts)
endef

#define $(package)_config_cmds
#  $($(package)_autoconf)
#endef

define $(package)_build_cmds
  $(MAKE) CPPFLAGS='-fPIC' -j1 src/libwolfssl.la
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install-libLTLIBRARIES install-includeHEADERS install-nobase_includeHEADERS install-pkgconfigDATA
endef

#define $(package)_postprocess_cmds
#  rm -rf bin share
#endef
