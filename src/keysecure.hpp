#pragma once

#include <stdio.h>
#include <exception>
#include <fstream>
#include <map>
#include <string>
#include <vector>

namespace kfp {
using StringSeq = std::vector<std::string>;
using Entry = std::map<std::string, std::string>;

class Keysecure {
 public:
  Keysecure(std::string key_database, std::string config, std::string password);
  std::vector<Entry> get_db() const;
  void save_entry(Entry entry, std::string title = "");
  void delete_entry(std::string value);
  void get_entry(Entry entry);

 private:
  const std::string key_database;
  const std::string config;
  const StringSeq keys;

  void check_entry(Entry values) throw();
  void match_password(std::string password) const throw();
  void create_db(std::string password) const;
  Entry read_config() const;
  const StringSeq get_keys() const;
};

const std::string get_password();
const std::string sha256(const std::string& str);
const std::string get_hash_from_file(std::string file_name);
StringSeq cut_line(std::string line, const std::string& delimiter = ",");
StringSeq read_netstring_line(std::string line, std::string delimiter = ":");

class InvalidEntry : public std::exception {
  const char* what() const throw() {
    return "Invalid entry. Probably some key not fit to pattern from conf ";
  }
};

class WrongPassword : public std::exception {
  const char* what() const throw() { return "Invalid password was provided"; }
};

}  // namespace kfp
