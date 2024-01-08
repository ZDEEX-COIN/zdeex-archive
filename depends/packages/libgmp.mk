package=libgmp

ifeq ($(host_os),mingw32)
$(package)_download_path=https://github.com/radix42/$(package)/archive
$(package)_file_name=$(package)-$($(package)_git_commit).tar.gz
$(package)_download_file=$($(package)_git_commit).tar.gz
$(package)_sha256_hash=67df06ed50f288bd7b1ec6907973684fb7cf1196f2cb368b59d423e42b065e40
$(package)_git_commit=42ba95387cdfd67399f7aac52fddb8d6e1258ee6
$(package)_dependencies=
$(package)_config_opts=--enable-cxx --disable-shared
else ifeq ($(build_os),darwin)
$(package)_version=6.1.1
$(package)_download_path=https://git.hush.is/attachments
$(package)_file_name=d613c855-cd92-4efb-b893-658496852019
$(package)_download_file=d613c855-cd92-4efb-b893-658496852019
$(package)_sha256_hash=a8109865f2893f1373b0a8ed5ff7429de8db696fc451b1036bd7bdf95bbeffd6
$(package)_config_opts=--enable-cxx --disable-shared
else
$(package)_version=6.1.1
$(package)_download_path=https://ftp.gnu.org/gnu/gmp
$(package)_file_name=gmp-$($(package)_version).tar.bz2
$(package)_sha256_hash=a8109865f2893f1373b0a8ed5ff7429de8db696fc451b1036bd7bdf95bbeffd6
$(package)_dependencies=
$(package)_config_opts=--enable-cxx --disable-shared
endif

define $(package)_config_cmds
  $($(package)_autoconf) --host=$(host) --build=$(build)
endef

ifeq ($(build_os),darwin)
define $(package)_build_cmds
	$(MAKE)
endef
else
define $(package)_build_cmds
  $(MAKE) CPPFLAGS='-fPIC'
endef
endif

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install ; echo '=== staging find for $(package):' ; find $($(package)_staging_dir)
endef
