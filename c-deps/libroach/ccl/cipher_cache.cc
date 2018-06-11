// Copyright 2017 The Cockroach Authors.
//
// Licensed as a CockroachDB Enterprise file under the Cockroach Community
// License (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
//     https://github.com/cockroachdb/cockroach/blob/master/licenses/CCL.txt

#include "cipher_cache.h"
#include "crypto_utils.h"

// Max ciphers cached per key ID.
static const size_t kMaxQueueSize = 100;

class CipherCache::CipherWrapper : public rocksdb_utils::BlockCipher {
 public:
  CipherWrapper(CipherCache* cache, const std::string& key_id, rocksdb_utils::BlockCipher* cipher)
      : cache_(cache), key_id_(key_id), cipher_(cipher) {}

  ~CipherWrapper() { cache_->Release(key_id_, cipher_); }

  size_t BlockSize() { return cipher_->BlockSize(); }
  rocksdb::Status Encrypt(char* data) { return cipher_->Encrypt(data); }
  rocksdb::Status Decrypt(char* data) { return cipher_->Decrypt(data); }

 private:
  CipherCache* cache_;
  std::string key_id_;
  rocksdb_utils::BlockCipher* cipher_;
};
CipherCache::CipherCache() {}

void CipherCache::GetCipher(const enginepbccl::SecretKey* key,
                            std::unique_ptr<rocksdb_utils::BlockCipher>* result) {
  std::unique_lock<std::mutex> l(mu_);
  auto deq = map_[key->info().key_id()];

  rocksdb_utils::BlockCipher* cipher;
  if (deq.empty()) {
    cipher = NewAESEncryptCipher(key);
  } else {
    cipher = deq.front();
    deq.pop_front();
  }

  result->reset(new CipherWrapper(this, key->info().key_id(), cipher));
}

void CipherCache::Release(const std::string& key_id, rocksdb_utils::BlockCipher* cipher) {
  std::unique_lock<std::mutex> l(mu_);
  auto deq = map_[key_id];

  if (deq.size() >= kMaxQueueSize) {
    // Max size reached, don't keep it.
    delete cipher;
    return;
  }

  deq.push_back(cipher);
}

CipherCache::~CipherCache() {
  // We need to delete things ourselves, we're using raw pointers.
  for (auto map_iter = map_.begin(); map_iter != map_.end(); ++map_iter) {
    auto deq = map_iter->second;
    for (auto deq_iter = deq.begin(); deq_iter != deq.end(); ++deq_iter) {
      delete *deq_iter;
    }
    deq.clear();
  }
}
