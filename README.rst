Keysecure (work in progress)
############################
Store your data in a safe, fast and convenient way.

Build dependencies
##################
- openssl
- make
- g++
- gtest (optional for testing)

Install dependencies:
---------------------
      **Arch linux:**
      `sudo pacman -S openssl make g++ gtest`

Build steps:
------------
      **Source:**
         `make`
      **Tests:**
         `cd tests/; make && make run`

Docker image:
-------------
  | `docker pull xaar/keysecure`
  | `docker container run -it xaar/keysecure`

TODO
####
- Implement database encryption
- Delete/Search functionality
- Refactoring


License
#######
- MIT
