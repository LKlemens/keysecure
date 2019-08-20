#include <gtest/gtest.h>
#include <fstream>
#include <iostream>
#include "keysecure.hpp"

TEST(TestKeysecure, check_amount_of_entries) {
  kfp::Keysecure key("test_db.kfp", "conf", "123456");
  std::vector<kfp::Entry> all_entries = key.get_db();
  ASSERT_EQ(2, all_entries.size());
}

TEST(TestKeysecure, check_entry_values) {
  kfp::Keysecure key("test_db.kfp", "conf", "123456");
  std::vector<kfp::Entry> all_entries = key.get_db();
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
  std::remove(db_name.c_str());
  kfp::Keysecure key(db_name, "conf", "123456");
  std::ifstream file(db_name);
  ASSERT_EQ(file.good(), true);

  int num_of_line = 0;
  std::string line;
  while (std::getline(file, line)) ++num_of_line;
  ASSERT_EQ(num_of_line, 0);
  std::remove(db_name.c_str());
}

TEST(TestKeysecure, add_new_entry) {
  std::string db_name = "newdatabase_add.kfp";
  std::remove(db_name.c_str());
  kfp::Keysecure key(db_name, "conf", "123456");

  kfp::Entry entry;
  entry["title"] = "po=lo";
  entry["username"] = "bob@gmail.com";
  entry["url"] = "netflix.com";
  entry["path"] = "";
  entry["password"] = "qwerty;;;,,,, sdf";
  entry["notes"] = "netflix is awesome";
  key.add_entry(entry);

  std::vector<kfp::Entry> all_entries = key.get_db();
  kfp::Entry entry_from_file = all_entries[0];
  ASSERT_EQ(entry_from_file["title"], "po=lo");
  ASSERT_EQ(entry_from_file["username"], "bob@gmail.com");
  ASSERT_EQ(entry_from_file["url"], "netflix.com");
  ASSERT_EQ(entry_from_file["path"], "");
  ASSERT_EQ(entry_from_file["password"], "qwerty;;;,,,, sdf");
  ASSERT_EQ(entry_from_file["notes"], "netflix is awesome");

  // check whether it open db properly
  kfp::Keysecure key_again(db_name, "conf", "123456");
  std::remove(db_name.c_str());
}

TEST(TestKeysecure, delete_entry) {
  std::string db_name = "newdatabase_delete.kfp";
  std::remove(db_name.c_str());
  kfp::Keysecure key(db_name, "conf", "123456");

  kfp::Entry entry1;
  entry1["title"] = "polo";
  entry1["username"] = "bob@gmail.com";
  entry1["url"] = "netflix.com";
  entry1["path"] = "of life";
  entry1["password"] = "qwerty;;;,,,, sdf";
  entry1["notes"] = "netflix is awesome";
  key.add_entry(entry1);
  kfp::Entry entry2;
  entry2["title"] = "hoho";
  entry2["username"] = "bob@gmail.com";
  entry2["url"] = "netflix.com";
  entry2["path"] = "of life";
  entry2["password"] = "qwerty;;;,,,, sdf";
  entry2["notes"] = "netflix is awesome";
  key.add_entry(entry2);

  std::vector<kfp::Entry> all_entries = key.get_db();
  ASSERT_EQ(all_entries.size(), 2);

  key.delete_entry(entry2);

  all_entries = key.get_db();
  ASSERT_EQ(all_entries.size(), 1);

  // check whether it open db properly
  kfp::Keysecure key_again(db_name, "conf", "123456");
  std::remove(db_name.c_str());
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  // ::testing::GTEST_FLAG(filter) = "*dd_new_entr*";
  return RUN_ALL_TESTS();
}
