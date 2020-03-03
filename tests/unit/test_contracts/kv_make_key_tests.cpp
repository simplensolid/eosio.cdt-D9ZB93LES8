#include <eosio/eosio.hpp>

struct testing_struct {
   uint16_t a;
   uint16_t b;

   bool operator==(const testing_struct& rhs) const {
      return a == rhs.a && b == rhs.b;
   }
};

struct my_struct {
   eosio::name tname;
   std::string tstring;
   uint64_t tui64;
   int32_t ti32;
   uint128_t tui128;
   float tfloat;
   double tdouble;
   testing_struct tstruct;
   std::tuple<uint64_t, float, std::string> ttuple;

   bool operator==(const my_struct& rhs) const {
      return tname == rhs.tname &&
             tstring == rhs.tstring &&
             tui64 == rhs.tui64 &&
             ti32 == rhs.ti32 &&
             tui128 == rhs.tui128 &&
             tfloat == rhs.tfloat &&
             tdouble == rhs.tdouble &&
             tstruct == rhs.tstruct &&
             ttuple == rhs.ttuple;
   }

   auto itstring() const { return eosio::make_insensitive(tstring); }
};

struct my_table : eosio::kv_table<my_struct> {
   kv_unique_index<eosio::name>                              tname{&my_struct::tname};
   kv_unique_index<std::string>                              tstring{&my_struct::tstring};
   kv_unique_index<uint64_t>                                 tui64{&my_struct::tui64};
   kv_unique_index<int32_t>                                  ti32{&my_struct::ti32};
   kv_unique_index<uint128_t>                                tui128{&my_struct::tui128};
   kv_unique_index<float>                                    tfloat{&my_struct::tfloat};
   kv_unique_index<double>                                   tdouble{&my_struct::tdouble};
   kv_unique_index<testing_struct>                           tstruct{&my_struct::tstruct};
   kv_unique_index<std::tuple<uint64_t, float, std::string>> ttuple{&my_struct::ttuple};
   kv_unique_index<eosio::key_type>                          itstring{&my_struct::itstring};

   my_table(eosio::name contract_name) {
      init(contract_name, "testtable"_n, "eosio.kvram"_n, &tname, &tstring, &tui64, &ti32, &tui128, &tfloat, &tdouble, &tstruct, &ttuple, &itstring);
   }
};

class [[eosio::contract]] kv_make_key_tests : public eosio::contract {
public:
   using contract::contract;

   template <typename I>
   void check_index(I& idx, const std::vector<my_struct>& expected) {
      auto end_itr = idx.end();
      auto itr = idx.begin();

      for (const auto& expect : expected) {
         eosio::check(itr != end_itr, "Should not be the end");
         eosio::check(itr.value() == expect, "Got the wrong value");
         ++itr;
      }
      eosio::check(itr == end_itr, "Should be the end");
   }

   my_struct s1{
      .tname = "bob"_n,
      .tstring = "a",
      .tui64 = 5,
      .ti32 = 0,
      .tui128 = 1000,
      .tfloat = 4.2574,
      .tdouble = 4.2574,
      .tstruct = { 1, 2 },
      .ttuple = { 100, 32.43, "abc"}
   };
   my_struct s2{
      .tname = "alice"_n,
      .tstring = "C",
      .tui64 = 4,
      .ti32 = -1,
      .tui128 = 0,
      .tfloat = 5.2574,
      .tdouble = 50000.2574,
      .tstruct = { 5, 6 },
      .ttuple = { 100, 32.43, "def"}
   };
   my_struct s3{
      .tname = "john"_n,
      .tstring = "e",
      .tui64 = 3,
      .ti32 = -2,
      .tfloat = 187234,
      .tui128 = (static_cast<uint128_t>(1) << 127) - 1,
      .tdouble = 1872340000,
      .tstruct = { 3, 4 },
      .ttuple = { 100, 33.43, "abc"}
   };
   my_struct s4{
      .tname = "joe"_n,
      .tstring = "g",
      .tui64 = 2,
      .ti32 = 1,
      .tui128 = (static_cast<uint128_t>(1) << 127) - 2,
      .tfloat = 0,
      .tdouble = 0,
      .tstruct = { 7, 8 },
      .ttuple = { 101, 32.43, "abc"}
   };
   my_struct s5{
      .tname = "billy"_n,
      .tstring = "I",
      .tui64 = 1,
      .ti32 = 2,
      .tui128 = 54321,
      .tfloat = -4.2574,
      .tdouble = -40000.2574,
      .tstruct = { 9, 10 },
      .ttuple = { 101, 34.43, "abc"}
   };

   [[eosio::action]]
   void setup() {
      my_table t{"kvtest"_n};

      t.put(s1);
      t.put(s2);
      t.put(s3);
      t.put(s4);
      t.put(s5);
   }

   [[eosio::action]]
   void makekeyname() {
      my_table t{"kvtest"_n};
      check_index(t.tname, {s2, s5, s1, s4, s3});
   }

   [[eosio::action]]
   void makekeystr() {
      my_table t{"kvtest"_n};
      check_index(t.tstring, {s2, s5, s1, s3, s4});
   }

   [[eosio::action]]
   void makekeyistr() {
      my_table t{"kvtest"_n};
      check_index(t.itstring, {s1, s2, s3, s4, s5});
   }

   [[eosio::action]]
   void makekeyuill() {
      my_table t{"kvtest"_n};
      check_index(t.tui64, {s5, s4, s3, s2, s1});
   }

   [[eosio::action]]
   void makekeyil() {
      my_table t{"kvtest"_n};
      check_index(t.ti32, {s3, s2, s1, s4, s5});
   }

   [[eosio::action]]
   void makekeyuilll() {
      my_table t{"kvtest"_n};
      check_index(t.tui128, {s2, s1, s5, s4, s3});
   }

   [[eosio::action]]
   void makekeyflt() {
      my_table t{"kvtest"_n};
      check_index(t.tfloat, {s5, s4, s1, s2, s3});
   }

   [[eosio::action]]
   void makekeydbl() {
      my_table t{"kvtest"_n};
      check_index(t.tdouble, {s5, s4, s1, s2, s3});
   }

   [[eosio::action]]
   void makekeystct() {
      my_table t{"kvtest"_n};
      check_index(t.tstruct, {s1, s3, s2, s4, s5});
   }

   [[eosio::action]]
   void makekeytup() {
      my_table t{"kvtest"_n};
      check_index(t.ttuple, {s1, s2, s3, s4, s5});
   }
};
