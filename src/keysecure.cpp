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

Keysecure::Keysecure(std::string database_path, std::string config,
                     std::string pass)
    : database_path(database_path),
      keys(get_keys(config)),
      password(pass.begin(), pass.end()) {
  std::ifstream file(database_path);

  if (!file.good()) {
    create_db();
  }

  file.close();
}

std::vector<Entry> Keysecure::to_vector_of_entries(
    const Botan::secure_vector<uint8_t> secure_vec) const {
  std::string netstrings(secure_vec.begin(), secure_vec.end());
  auto passwrods_lines = read_netstring_line(netstrings);
  std::vector<Entry> entries;
  for (auto line : passwrods_lines) {
    Entry entry;
    auto fields = read_netstring_line(line);
    for (std::size_t i = 0; i < fields.size(); i = i + 2) {
      entry[fields[i]] = fields[i + 1];
    }
    if (entry.size() == keys.size()) {
      entries.push_back(entry);
    }
  }
  return entries;
}

std::vector<Entry> Keysecure::get_db() const { return decrypt(); }

void Keysecure::add_entry(Entry entry) throw() {
  check_entry(entry);
  auto all_entries = decrypt();
  all_entries.push_back(entry);
  encrypt(all_entries);
}

int Keysecure::delete_entry(Entry dentry) {
  auto all_entries = decrypt();
  int code = 1;
  for (std::size_t i = 0; i <= all_entries.size(); ++i) {
    if (all_entries[i] == dentry) {
      all_entries.erase(all_entries.begin() + i);
      code = 0;
    }
  }
  encrypt(all_entries);
  return code;
}

void Keysecure::check_entry(Entry entry) const throw() {
  for (auto m : entry) {
    if (std::find(keys.begin(), keys.end(), m.first) == keys.end()) {
      throw InvalidEntry();
    }
  }
}

void Keysecure::create_db() const {
  std::ofstream file(database_path);
  file.close();
}

const StringSeq Keysecure::get_keys(std::string config) const {
  std::ifstream file(config);

  std::string line;
  std::getline(file, line);
  StringSeq keys = cut_line(line, " ");
  file.close();
  return keys;
}

void Keysecure::encrypt(std::vector<Entry> all_entries) {
  std::string netstring_data = to_netstring(all_entries);
  Botan::secure_vector<uint8_t> input(netstring_data.begin(),
                                      netstring_data.end());
  auto encrypted_entries_output =
      encrypt_decrypt(input, password, Botan::Cipher_Dir::ENCRYPTION);
  std::ofstream outFile(database_path);
  for (auto x : encrypted_entries_output) outFile << x;
  outFile.close();
}

std::vector<Entry> Keysecure::decrypt() const {
  std::ifstream inputFile(database_path);
  std::string str((std::istreambuf_iterator<char>(inputFile)),
                  std::istreambuf_iterator<char>());
  inputFile.close();
  if (str == "") {
    return std::vector<Entry>();
  }

  Botan::secure_vector<uint8_t> input(str.begin(), str.end());
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
  std::string entry_netstring, main_netstring;
  for (auto entry : entries) {
    for (auto key : entry) {
      entry_netstring +=
          std::to_string(key.first.length()) + ":" + key.first + ",";
      entry_netstring +=
          std::to_string(key.second.length()) + ":" + key.second + ",";
    }
    main_netstring +=
        std::to_string(entry_netstring.length()) + ":" + entry_netstring + ",";
    entry_netstring = "";
  }
  return main_netstring;
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
    Botan::secure_vector<uint8_t> &input,
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

  // encrypt/decrypt input container in place
  processor->finish(input);

  return input;
}

}  // namespace kfp
