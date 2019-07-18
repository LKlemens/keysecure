#pragma once

#include <botan/aead.h>
#include <botan/hex.h>
#include <botan/kdf.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <exception>
#include <fstream>
#include <map>
#include <string>
#include <vector>

namespace kfp {
using StringSeq = std::vector<std::string>;
using Entry =
    std::map<std::string, std::string>;  // type : value , e.g. password : 12345

class Keysecure {
 public:
  Keysecure(std::string key_database, std::string config, const char *password);
  std::vector<Entry> to_vector_of_entries(
      const Botan::secure_vector<uint8_t> sec_vec);
  std::vector<Entry> get_db();
  void add_entry(Entry entry) throw();
  int delete_entry(Entry dentry);
  std::vector<Entry> decrypt();
  void encrypt();
  std::vector<Entry> all_entries;
  std::string compress_db();

 private:
  const std::string key_database;
  const std::string config;
  const StringSeq keys;
  const std::string password;

  void check_entry(Entry values) throw();
  void create_db() const;
  Entry read_config() const;
  const StringSeq get_keys() const;
};

std::string get_password();
StringSeq cut_line(std::string line, const std::string &delimiter = ",");
StringSeq read_netstring_line(std::string line, std::string delimiter = ":");

class InvalidEntry : public std::exception {
  const char *what() const throw() {
    return "Invalid entry. Probably some key not fit to pattern from conf ";
  }
};

class WrongPassword : public std::exception {
  const char *what() const throw() { return "Invalid password was provided"; }
};

}  // namespace kfp
