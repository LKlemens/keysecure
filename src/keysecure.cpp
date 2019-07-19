#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <limits>
#include <sstream>
#include "keysecure.hpp"
namespace kfp {

/*######################################################################
 *
 *                    Keysecure methods
 *
 *######################################################################*/

Keysecure::Keysecure(std::string key_database, std::string config,
                     std::string pass)
    : key_database(key_database),
      config(config),
      keys(get_keys()),
      password(pass.begin(), pass.end()) {
  std::ifstream file(key_database);

  std::cout << "invoke ctor " << std::endl;
  all_entries.reserve(30);

  if (!file.good()) {
    create_db();
  } else {
    all_entries = decrypt();
  }

  file.close();
}

std::vector<Entry> Keysecure::to_vector_of_entries(
    const Botan::secure_vector<uint8_t> secure_vec) {
  std::string s(secure_vec.begin(), secure_vec.end());
  auto passwrods_lines = cut_line(s, "\n");
  std::cout << "pass in getdb" << std::endl;
  std::cout << s << std::endl;
  std::cout << "pass in getdb" << std::endl;
  std::vector<Entry> entries;
  for (auto line : passwrods_lines) {
    Entry entry;
    auto fields = read_netstring_line(line);
    for (auto field : fields) {
      auto key_value = cut_line(field, "=");
      entry[key_value[0]] = key_value[1];
    }
    if (entry.size() == keys.size()) {
      entries.push_back(entry);
    }
  }
  std::cout << "entries" << std::endl;
  for (auto x : entries) std::cout << x["title"] << std::endl;
  std::cout << "entries" << std::endl;
  return entries;
}

std::vector<Entry> Keysecure::get_db() { return all_entries; }

void Keysecure::add_entry(Entry entry) throw() {
  check_entry(entry);
  all_entries.push_back(entry);
  encrypt();
}

int Keysecure::delete_entry(Entry dentry) {
  std::cout << "size before entry" << std::endl;
  std::cout << all_entries.size() << std::endl;
  int code = 1;
  for (std::size_t i = 0; i <= all_entries.size(); ++i) {
    if (all_entries[i] == dentry) {
      std::cout << "in for value " << all_entries[i]["title"] << std::endl;
      all_entries.erase(all_entries.begin() + i);
      code = 0;
    }
  }
  std::cout << "size before after" << std::endl;
  std::cout << all_entries.size() << std::endl;
  encrypt();
  return code;
}

void Keysecure::check_entry(Entry entry) throw() {
  for (auto m : entry) {
    if (std::find(keys.begin(), keys.end(), m.first) == keys.end()) {
      throw InvalidEntry();
    }
  }
}

void Keysecure::create_db() const {
  std::ofstream file(key_database);
  file.close();
}

const StringSeq Keysecure::get_keys() const {
  std::ifstream file(config);

  std::string line;
  std::getline(file, line);
  StringSeq keys = cut_line(line, " ");
  file.close();
  return keys;
}

void Keysecure::encrypt() {
  std::cout << "encrypt fun pass: " << std::endl;
  std::cout << "encrypt file ???????????????????????????????" << std::endl;

  std::string netstring_data = to_netstring(all_entries);
  const std::vector<uint8_t> input(netstring_data.begin(),
                                   netstring_data.end());
  std::cout << std::endl;
  auto out = encrypt_decrypt(input, password, Botan::Cipher_Dir::ENCRYPTION);
  std::ofstream outFile(key_database);
  for (auto x : out) outFile << x;
}

std::vector<Entry> Keysecure::decrypt() {
  std::ifstream t(key_database);
  std::string str((std::istreambuf_iterator<char>(t)),
                  std::istreambuf_iterator<char>());

  std::cout << "decrypt file ???????????????????????????????" << std::endl;

  const std::vector<uint8_t> input(str.begin(), str.end());
  auto data_u8 =
      encrypt_decrypt(input, password, Botan::Cipher_Dir::DECRYPTION);

  return to_vector_of_entries(data_u8);
}

/*######################################################################
 *
 *                            Functions
 *
 *######################################################################*/

std::string to_netstring(std::vector<Entry> entries) {
  std::string pass_str;
  std::string entrystr;
  for (auto entires : entries) {
    for (auto key : entires) {
      entrystr = key.first + "=" + key.second;
      pass_str += std::to_string(entrystr.length()) + ":" + entrystr + ",";
    }
    if (entires != *entries.rbegin()) {
      pass_str += '\n';
    }
  }
  return pass_str;
}

StringSeq cut_line(std::string line, const std::string &delimiter) {
  StringSeq entry_vec;
  entry_vec.reserve(8);
  size_t pos = 0;
  std::string token;
  while ((pos = line.find(delimiter)) != std::string::npos) {
    token = line.substr(0, pos);
    entry_vec.push_back(token);
    line.erase(0, pos + delimiter.length());
  }
  entry_vec.push_back(line);

  return entry_vec;
}

bool is_number(const std::string &s) {
  return !s.empty() && std::all_of(s.begin(), s.end(), ::isdigit);
}

StringSeq read_netstring_line(std::string line, std::string delimiter) {
  StringSeq entry_vec;
  entry_vec.reserve(8);
  size_t pos = 0;
  while ((pos = line.find(delimiter)) != std::string::npos) {
    int len_of_netstring = 0;
    if (is_number(line.substr(0, pos))) {
      len_of_netstring = std::stoi(line.substr(0, pos));
    } else
      break;
    line.erase(0, pos + delimiter.length());
    entry_vec.push_back(line.substr(0, len_of_netstring));
    char len_of_comma = 1;
    line.erase(0, len_of_netstring + len_of_comma);
  }
  return entry_vec;
}

const Botan::secure_vector<uint8_t> encrypt_decrypt(
    const std::vector<uint8_t> &input,
    const Botan::secure_vector<uint8_t> &password,
    Botan::Cipher_Dir direction) {
  std::string mode = "ChaCha20Poly1305";

  Botan::KDF *key_p = Botan::get_kdf("KDF2(SHA-512)");
  auto key_hex = key_p->derive_key(32, password);

  const std::string iv_hex = "FFFFFFFFFFFFFFFFFFFFFFFF";
  const std::string ad_hex = "000fffff";

  const Botan::SymmetricKey key(key_hex);
  const Botan::InitializationVector iv(iv_hex);
  const std::vector<uint8_t> ad = Botan::hex_decode(ad_hex);

  std::unique_ptr<Botan::Cipher_Mode> processor(
      Botan::Cipher_Mode::create(mode, direction));
  if (!processor) std::cout << "Cipher algorithm not found" << std::endl;

  // Set key
  processor->set_key(key);

  if (Botan::AEAD_Mode *aead =
          dynamic_cast<Botan::AEAD_Mode *>(processor.get())) {
    aead->set_ad(ad);
  } else if (ad.size() != 0) {
    std::cout << "Cannot specify associated data with non-AEAD mode"
              << std::endl;
  }

  // Set IV
  processor->start(iv.bits_of());

  Botan::secure_vector<uint8_t> result(input.begin(), input.end());
  processor->finish(result);

  return result;
}

}  // namespace kfp
