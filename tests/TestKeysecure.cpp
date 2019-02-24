#include <gtest/gtest.h>
#include <cstdio>
#include <fstream>
#include <iostream>
#include "keysecure.hpp"

TEST(TestKeysecure, check_amount_of_entries) {
  kfp::Keysecure key("test_db.kfp", "conf");
  std::vector<kfp::Entry> all_entries = key.read_from_db();
  ASSERT_EQ(2, all_entries.size());
}

TEST(TestKeysecure, check_entry_values) {
  kfp::Keysecure key("test_db.kfp", "conf");
  std::vector<kfp::Entry> all_entries = key.read_from_db();
  kfp::Entry entry = all_entries[0];
  ASSERT_EQ(entry["notes"], "gmail is from google");
  ASSERT_EQ(entry["password"], "123456 PPP");
  ASSERT_EQ(entry["path"], "");
  ASSERT_EQ(entry["title"], "gmail");
  ASSERT_EQ(entry["url"], "gmail.com");
  ASSERT_EQ(entry["username"], "bob@gmail.com");

  entry = all_entries[1];
  ASSERT_EQ(entry["notes"], "netflix is awesome");
  ASSERT_EQ(entry["password"], "qwerty;;;,,,, sdf");
  ASSERT_EQ(entry["path"], "");
  ASSERT_EQ(entry["title"], "netflix.com");
  ASSERT_EQ(entry["url"], "netflix");
  ASSERT_EQ(entry["username"], "bob@gmail.com");
}

TEST(TestKeysecure, create_new_database) {
  std::string db_name = "newdatabase.kfp";
  kfp::Keysecure key(db_name, "conf");
  std::ifstream file(db_name);
  ASSERT_EQ(file.good(), true);

  int num_of_line = 0;
  std::string line;
  while (std::getline(file, line)) ++num_of_line;
  ASSERT_EQ(num_of_line, 1);

  std::remove(db_name.c_str());
}

TEST(TestKeysecure, add_new_entry) {
  std::string db_name = "newdatabase_add.kfp";
  kfp::Keysecure key(db_name, "conf");

  kfp::Entry entry;
  entry["title"] = "polo";
  entry["username"] = "bob@gmail.com";
  entry["url"] = "netflix.com";
  entry["path"] = "of life";
  entry["password"] = "qwerty;;;,,,, sdf";
  entry["notes"] = "netflix is awesome";
  key.write_to_db(entry);

  std::vector<kfp::Entry> all_entries = key.read_from_db();
  kfp::Entry entry_from_file = all_entries[0];
  ASSERT_EQ(entry["title"], "polo");
  ASSERT_EQ(entry["username"], "bob@gmail.com");
  ASSERT_EQ(entry["url"], "netflix.com");
  ASSERT_EQ(entry["path"], "of life");
  ASSERT_EQ(entry["password"], "qwerty;;;,,,, sdf");
  ASSERT_EQ(entry["notes"], "netflix is awesome");

  // check whether it open db properly
  kfp::Keysecure key_again(db_name, "conf");
  std::remove(db_name.c_str());
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
