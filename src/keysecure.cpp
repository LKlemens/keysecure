#include <algorithm>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include "keysecure.hpp"
#include "openssl/sha.h"

namespace kfp {

/*######################################################################
 *
 *                    Keysecure methods
 *
 *######################################################################*/

Keysecure::Keysecure(std::string key_database, std::string config,
                     std::string password)
    : key_database(key_database), config(config), keys(get_keys()) {
  std::ifstream file(key_database);

  if (!file.good())
    create_db(password);
  else
    match_password(password);
  file.close();
}

std::vector<Entry> Keysecure::read_from_db() const {
  std::ifstream file(key_database);
  file.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

  std::vector<Entry> all_entries;
  all_entries.reserve(30);

  for (std::string line; std::getline(file, line);) {
    Entry entry;
    auto fields = read_netstring_line(line);
    for (auto field : fields) {
      auto key_value = cut_line(field, "=");
      entry[key_value[0]] = key_value[1];
    }
    all_entries.push_back(entry);
  }
  file.close();
  return all_entries;
}

void Keysecure::write_to_db(Entry entry) {
  check_entry(entry);
  std::ofstream file(key_database, std::ios::app);
  if (!file.is_open()) {
    std::cerr << "Error opend file" << std::endl;
    exit(1);
  }
  std::string entrystr;
  for (auto m : entry) {
    entrystr = m.first + "=" + m.second;
    file << entrystr.length() << ":" + entrystr + ",";
  }
  file << std::endl;
  file.close();
}

void Keysecure::check_entry(Entry entry) throw() {
  for (auto m : entry) {
    if (std::find(keys.begin(), keys.end(), m.first) == keys.end()) {
      throw InvalidEntry();
    }
  }
}

void Keysecure::match_password(std::string password) const {
  std::string hash_from_file = kfp::get_hash_from_file(key_database);
  if (password.empty()) {
    password = kfp::get_password();
  }
  std::string pass_hash = kfp::sha256(password);
  if (pass_hash != hash_from_file) {
    std::cerr << "ERROR: Wrong password!" << std::endl;
    exit(1);
  }
}

void Keysecure::create_db(std::string password) const {
  std::ofstream file(key_database);
  if (password.empty()) {
    password = kfp::get_password();
  }
  std::string pass_hash = kfp::sha256(password);
  file << pass_hash << std::endl;
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

const std::string get_password() {
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

const std::string sha256(const std::string& str) {
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, str.c_str(), str.size());
  SHA256_Final(hash, &sha256);
  std::stringstream ss;
  for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
  }
  return ss.str();
}

const std::string get_hash_from_file(std::string file_name) {
  std::ifstream file(file_name);
  std::string hash;
  std::getline(file, hash);
  file.close();
  return hash;
}

StringSeq cut_line(std::string line, const std::string& delimiter) {
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

StringSeq read_netstring_line(std::string line, std::string delimiter) {
  StringSeq entry_vec;
  entry_vec.reserve(8);
  size_t pos = 0;
  while ((pos = line.find(delimiter)) != std::string::npos) {
    int len_of_netstring = std::stoi(line.substr(0, pos));
    line.erase(0, pos + delimiter.length());
    entry_vec.push_back(line.substr(0, len_of_netstring));
    char len_of_comma = 1;
    line.erase(0, len_of_netstring + len_of_comma);
  }
  if (line != "") entry_vec.push_back(line);

  return entry_vec;
}

}  // namespace kfp
