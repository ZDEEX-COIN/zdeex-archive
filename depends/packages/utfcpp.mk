$(package)_version=3.1
$(package)_download_path=https://git.hush.is/attachments
$(package)_file_name=11822fe4-3846-4ce4-9c84-ba0877a7b186
$(package)_download_file=11822fe4-3846-4ce4-9c84-ba0877a7b186
$(package)_sha256_hash=ab531c3fd5d275150430bfaca01d7d15e017a188183be932322f2f651506b096

define $(package)_stage_cmds
  cp -a ./source $($(package)_staging_dir)$(host_prefix)/include
endef
