# Fills in the profile fields a realm user needs to log in, keeping any that the
# user already declares. The last name is the username without the "parity-"
# prefix, each part capitalized: parity-r29-level-m2m becomes R29LevelM2M.
def profile:
  .firstName //= "Parity"
  | .lastName //= (.username | ltrimstr("parity-") | split("-")
      | map(if test("^([a-z][0-9]+|m2m)$") then ascii_upcase
            else (.[:1] | ascii_upcase) + .[1:] end)
      | join(""))
  | .email //= (.username + "@example.test");
