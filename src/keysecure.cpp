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
                     const char *pass)
    : key_database(key_database),
      config(config),
      keys(get_keys()),
      password(pass) {
  std::ifstream file(key_database);

  std::cout << "invoke ctor " << password << std::endl;
  all_entries.reserve(30);

  if (!file.good()) {
    create_db();
  } else {
    decrypt();
    all_entries = get_db();
    compress_db();
  }

  file.close();
}

std::vector<Entry> Keysecure::get_db() {
  auto passwrods_lines = cut_line(plain_data, "\n");
  std::cout << "pass in getdb" << std::endl;
  std::cout << plain_data << std::endl;
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

void Keysecure::compress_db() {
  std::string pass_str;
  std::string entrystr;
  for (auto entires : all_entries) {
    for (auto key : entires) {
      entrystr = key.first + "=" + key.second;
      pass_str += std::to_string(entrystr.length()) + ":" + entrystr + ",";
    }
    if (entires != *all_entries.rbegin()) {
      pass_str += '\n';
    }
  }
  std::cout << "compress db before" << std::endl;
  std::cout << plain_data << std::endl;
  plain_data = pass_str;
  std::cout << "compress db after" << std::endl;
  std::cout << plain_data << std::endl;
}

void Keysecure::add_entry(Entry entry) {
  std::cout << "password in add entry " << password << std::endl;
  std::string pass_str, entrystr;
  for (auto m : entry) {
    entrystr = m.first + "=" + m.second;
    pass_str += std::to_string(entrystr.length()) + ":" + entrystr + ",";
    // std::cout << std::to_string(entrystr.length()) + ":" + entrystr + ","
    //           << std::endl;
  }
  pass_str += '\n';

  plain_data += pass_str;
  std::cout << "getdb size before " << all_entries.size() << std::endl;
  all_entries = get_db();
  std::cout << "getdb size after " << all_entries.size() << std::endl;
  encrypt();
}

void Keysecure::delete_entry(std::string value) {
  std::cout << "size before entry" << std::endl;
  std::cout << all_entries.size() << std::endl;
  for (auto it = all_entries.begin(); it != all_entries.end(); ++it) {
    std::cout << "in for value " << (*it)["title"] << std::endl;
    if ((*it)["title"] == value) {
      std::cout << "erase!!###########$$$$$$$$$$$$$ " << value << std::endl;
      all_entries.erase(it);
      break;
    }
  }
  std::cout << "size before after" << std::endl;
  std::cout << all_entries.size() << std::endl;
  compress_db();
  encrypt();
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

Entry Keysecure::read_config() const {
  Entry empty_entry;
  for (auto key : keys) {
    std::cout << key << std::endl;
    empty_entry[key] = "";
  }
  return empty_entry;
}

/*######################################################################
 *
 *                            Functions
 *
 *######################################################################*/

std::string get_password() {
  std::string pass;
// TODO: Get rid of preprocessor directives
#ifdef TEST
  pass = "123456";
#else
  std::cout << "Provide password: ";
  std::cin >> pass;
#endif
  std::cout << std::endl;
  return pass;
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
  // if (line != "") entry_vec.push_back(line);

  return entry_vec;
}

const Botan::secure_vector<uint8_t> encrypt_decrypt(
    const std::vector<uint8_t> &input, const std::string &key_str,
    Botan::Cipher_Dir direction) {
  std::string mode = "ChaCha20Poly1305";

  Botan::secure_vector<uint8_t> secret(key_str.begin(), key_str.end());

  Botan::KDF *key_p = Botan::get_kdf("KDF2(SHA-512)");
  auto key_hex = key_p->derive_key(32, secret);

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

int Keysecure::encrypt() {
  /* Open and truncate file to zero length or create ciphertext file for writing
   */
  std::cout << "encrypt fun pass: " << password << std::endl;
  std::cout << "encrypt file ???????????????????????????????" << std::endl;

  /* Encrypt the given file */
  // plain_data =
  //     "26:notes=gmail is from google,19:password=123456 "
  //     "PPP,5:path=,11:title=gmail,13:url=gmail.com,22:username=bob@gmail.com,"
  //     "\n"
  //     "24:notes=netflix is awesome,26:password=qwerty;;;,,,, "
  //     "sdf,5:path=,17:title=netflix.com,11:url=ne"
  //     "tflix,22:username=bob@gmail.com,";
  const std::vector<uint8_t> input(plain_data.begin(), plain_data.end());
  std::cout << std::endl;
  auto out = encrypt_decrypt(input, password, Botan::Cipher_Dir::ENCRYPTION);
  std::ofstream outFile(key_database);
  for (auto x : out) outFile << x;
  return 0;
}

int Keysecure::decrypt() {
  /* Open the encrypted file for reading in binary ("rb" mode) */
  std::ifstream t(key_database);
  std::string str((std::istreambuf_iterator<char>(t)),
                  std::istreambuf_iterator<char>());

  std::cout << "decrypt file ???????????????????????????????" << std::endl;
  /* Decrypt the given file */

  const std::vector<uint8_t> input(str.begin(), str.end());
  auto p = encrypt_decrypt(input, password, Botan::Cipher_Dir::DECRYPTION);
  std::string s(p.begin(), p.end());
  plain_data = s;
  std::cout << "after decrypt" << std::endl;
  std::cout << plain_data << std::endl;

  return 1;
}

}  // namespace kfp
