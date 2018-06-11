// Copyright 2017 The Cockroach Authors.
//
// Licensed as a CockroachDB Enterprise file under the Cockroach Community
// License (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
//     https://github.com/cockroachdb/cockroach/blob/master/licenses/CCL.txt

#pragma once

#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>
#include "../rocksdbutils/env_encryption.h"
#include "ccl/storageccl/engineccl/enginepbccl/key_registry.pb.h"

namespace enginepbccl = cockroach::ccl::storageccl::engineccl::enginepbccl;

// CipherCache keeps a cache of initialized ciphers to avoid initialization costs.
// TODO(mberhault): this hardcodes the use of AESEncryptCipher, we'll need to make it
// configurable if we ever add other ciphers (or have encrypt/decrypt AES).
class CipherCache {
 public:
  CipherCache();
  virtual ~CipherCache();

  // Assign a cipher to 'result'. It is released to the cache when destroyed.
  void GetCipher(const enginepbccl::SecretKey* key,
                 std::unique_ptr<rocksdb_utils::BlockCipher>* result);

 private:
  // The wrapper used to release the underlying Cipher upon destruction.
  class CipherWrapper;

  // Release is private as it is only meant to be called by the release-on-destruction
  // cipher wrapper.
  void Release(const std::string& key_id, rocksdb_utils::BlockCipher* cipher);

  typedef std::deque<rocksdb_utils::BlockCipher*> CipherQueue;
  typedef std::unordered_map<std::string, CipherQueue> IDMap;

  std::mutex mu_;
  IDMap map_;
};
