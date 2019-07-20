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
using Entry = std::map<std::string,
                       std::string>; /**< key : value , e.g. password : 12345 */

/** Class Keysecure represents keyring with paramount
 * functionalities.
 */
class Keysecure {
 public:
  /** Constructor a keyring.
   *
   * @param[in] key_database path to database
   * @param[in] config path to config, config define keys which will be used
   * @param[in] password pass to database
   */
  Keysecure(std::string key_database, std::string config, std::string password);

  /** Convert output from encrypt_decrypt function to vector of entries.
   *
   * @param[in] secure_vec vector of uint8 which includes entire decrypted
   * database
   *
   * @return readable vector of entries
   */
  std::vector<Entry> to_vector_of_entries(
      const Botan::secure_vector<uint8_t> secure_vec) const;

  /** Return copy of vector of entries
   *
   * @return copy of vector of entries
   */
  std::vector<Entry> get_db() const;

  /** Add entry to vector of entries
   */
  void add_entry(Entry entry) throw();

  /** Delete entry from vector of entries
   *
   * @return error code, 0 - successful , 1 - failed
   */
  int delete_entry(Entry dentry);

  /** Decrypt file with data and save it to readable vector of entires
   *
   * @return vector of entries with decrypted data from database
   */
  std::vector<Entry> decrypt() const;

  /** Enrypt data from all_entries in netstring encoding
   *
   * param[in] all_entries vector of entires to encrypt
   */
  void encrypt(std::vector<Entry> all_entries);

 private:
  const std::string key_database;
  const StringSeq keys;
  const Botan::secure_vector<uint8_t> password;

  /** Medhod checks if entry match up with definied keys
   */
  void check_entry(Entry values) const throw();

  /** Create database file if does not exist
   */
  void create_db() const;

  /** Get definied keys from config file
   *
   * @param[in] config path to config with definied keys
   * @return vector of keys
   */
  const StringSeq get_keys(std::string config) const;
};

/** Convert vector of entries to netstring encoding
 *
 * @param[in] vector of entires
 * @return netstring
 */
std::string to_netstring(std::vector<Entry> entries);

/** Cut line to vector of string by delimiter
 *
 * @param[in] line string line
 * @param[in] delimiter, default value is ","
 * @return vector of strings split by delimiter
 */
StringSeq cut_line(std::string line, const std::string &delimiter = ",");

/** Read netstring line and convert it to sequence of strings
 *
 * @param[in] line string line
 * @param[in] delimiter, default value is ":"
 * @return vector of string (entries)
 */
StringSeq read_netstring_line(std::string line, std::string delimiter = ":");

/** Encrypt/Decrypt by ChaCha20Poly1305 algorithm
 *
 * @param[in] input data to encrypt/decrypt
 * @param[in] password password for encrypt/decrypt
 * @param[in] direction Botan::Cipher_Dir definied encrypt/decrypt direction
 * @return vector of uint8 which has encrypted/decrypted data
 */
const Botan::secure_vector<uint8_t> encrypt_decrypt(
    const std::vector<uint8_t> &input,
    const Botan::secure_vector<uint8_t> &password, Botan::Cipher_Dir direction);

class InvalidEntry : public std::exception {
  const char *what() const throw() {
    return "Invalid entry. Probably some key not fit to pattern from conf ";
  }
};

class WrongPassword : public std::exception {
  const char *what() const throw() { return "Invalid password was provided"; }
};

}  // namespace kfp
