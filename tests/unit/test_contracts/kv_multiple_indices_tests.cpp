#include <eosio/eosio.hpp>

struct my_struct {
   eosio::name primary_key;
   std::string foo;
   uint64_t bar;
   int32_t baz;

   bool operator==(const my_struct b) const {
      return primary_key == b.primary_key &&
             foo == b.foo &&
             bar == b.bar &&
             baz == b.baz;
   }
};

struct my_table : eosio::kv_table<my_struct> {
   kv_unique_index<eosio::name>     primary_key{&my_struct::primary_key};
   kv_non_unique_index<std::string> foo{&my_struct::foo};
   kv_unique_index<uint64_t>        bar{&my_struct::bar};
   kv_non_unique_index<int32_t>     baz{&my_struct::baz};

   my_table(eosio::name contract_name) {
      init(contract_name, "testtable"_n, "eosio.kvram"_n, &primary_key, &foo, &bar, &baz);
   }
};

struct my_table2 : eosio::kv_table<my_struct> {
   kv_unique_index<eosio::name>  primary_key{&my_struct::primary_key};
   null_kv_index                 nullptr_2{&my_struct::foo};
   kv_non_unique_index<uint64_t> bar{&my_struct::bar};

   my_table2(eosio::name contract_name) {
      init(contract_name, "testtable"_n, "eosio.kvram"_n, &primary_key, &nullptr_2, &bar);
   }
};

struct my_table_idx : eosio::kv_table<my_struct> {
   kv_unique_index<eosio::name>     primary_key{"prim"_n, &my_struct::primary_key};
   kv_non_unique_index<std::string> foo{"f"_n, &my_struct::foo};

   my_table_idx(eosio::name contract_name) {
      init(contract_name, "testtable"_n, "eosio.kvram"_n, &primary_key, &foo);
   }
};

struct my_table_idx_err : eosio::kv_table<my_struct> {
   kv_unique_index<eosio::name>     primary_key{"prim"_n, &my_struct::primary_key};
   kv_non_unique_index<std::string> foo{&my_struct::foo};

   my_table_idx_err(eosio::name contract_name) {
      init(contract_name, "testtable"_n, "eosio.kvram"_n, &primary_key, &foo);
   }
};

struct my_table_idx_err_2 : eosio::kv_table<my_struct> {
   kv_unique_index<eosio::name>     primary_key{&my_struct::primary_key};
   kv_non_unique_index<std::string> foo{"f"_n, &my_struct::foo};

   my_table_idx_err_2(eosio::name contract_name) {
      init(contract_name, "testtable"_n, "eosio.kvram"_n, &primary_key, &foo);
   }
};

class [[eosio::contract]] kv_multiple_indices_tests : public eosio::contract {
public:
   using contract::contract;
   my_struct s1{
      .primary_key = "bob"_n,
      .foo = "a",
      .bar = 5,
      .baz = 2
   };
   my_struct s2{
      .primary_key = "alice"_n,
      .foo = "C",
      .bar = 4,
      .baz = 1
   };
   my_struct s3{
      .primary_key = "john"_n,
      .foo = "e",
      .bar = 3,
      .baz = 1
   };
   my_struct s4{
      .primary_key = "joe"_n,
      .foo = "g",
      .bar = 2,
      .baz = 1
   };
   my_struct s5{
      .primary_key = "billy"_n,
      .foo = "I",
      .bar = 1,
      .baz = 1
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
   void indices() {
      my_table_idx t{"kvtest"_n};
   }

   [[eosio::action]]
   void indiceserr() {
      my_table_idx_err t{"kvtest"_n};
   }

   [[eosio::action]]
   void indiceserr2() {
      my_table_idx_err_2 t{"kvtest"_n};
   }

   [[eosio::action]]
   void iteration() {
      my_table t{"kvtest"_n};

      auto foo_begin_itr = t.foo.begin();
      auto foo_end_itr = t.foo.end();

      auto bar_begin_itr = t.bar.begin();
      auto bar_end_itr = t.bar.end();

      auto foo_itr = t.foo.begin();
      auto bar_itr = t.bar.begin();

      eosio::check(foo_itr != foo_end_itr, "Should not be the end");
      eosio::check(bar_itr != bar_end_itr, "Should not be the end");
      eosio::check(foo_itr.value().foo == s2.foo, "Got the wrong value");
      eosio::check(bar_itr.value().bar == s5.bar, "Got the wrong value");

      ++foo_itr;
      ++bar_itr;
      eosio::check(foo_itr.value().foo == s5.foo, "Got the wrong value");
      eosio::check(bar_itr.value().bar == s4.bar, "Got the wrong value");

      ++foo_itr;
      ++bar_itr;
      eosio::check(foo_itr.value().foo == s1.foo, "Got the wrong value");
      eosio::check(bar_itr.value().bar == s3.bar, "Got the wrong value");

      ++foo_itr;
      ++bar_itr;
      eosio::check(foo_itr.value().foo == s3.foo, "Got the wrong value");
      eosio::check(bar_itr.value().bar == s2.bar, "Got the wrong value");

      ++foo_itr;
      ++bar_itr;
      eosio::check(foo_itr.value().foo == s4.foo, "Got the wrong value");
      eosio::check(bar_itr.value().bar == s1.bar, "Got the wrong value");

      ++foo_itr;
      ++bar_itr;
      eosio::check(foo_itr == foo_end_itr, "Should be the end");
      eosio::check(bar_itr == bar_end_itr, "Should be the end");

      --foo_itr;
      --bar_itr;
      eosio::check(foo_itr != foo_begin_itr, "Should not be the beginning");
      eosio::check(bar_itr != bar_begin_itr, "Should not be the beginning");

      --foo_itr;
      --bar_itr;
      eosio::check(foo_itr != foo_begin_itr, "Should not be the beginning");
      eosio::check(bar_itr != bar_begin_itr, "Should not be the beginning");

      --foo_itr;
      --bar_itr;
      eosio::check(foo_itr != foo_begin_itr, "Should not be the beginning");
      eosio::check(bar_itr != bar_begin_itr, "Should not be the beginning");

      --foo_itr;
      --bar_itr;
      eosio::check(foo_itr != foo_begin_itr, "Should not be the beginning");
      eosio::check(bar_itr != bar_begin_itr, "Should not be the beginning");

      --foo_itr;
      --bar_itr;
      eosio::check(foo_itr == foo_begin_itr, "Should be the beginning");
      eosio::check(bar_itr == bar_begin_itr, "Should be the beginning");
   }

   [[eosio::action]]
   void range() {
      my_table t{"kvtest"_n};

      std::vector<my_struct> expected = {s2, s5, s4, s3, s1};
      auto actual = t.baz.range(1l, 3l);

      eosio::check(actual == expected, "range did not return expected vector");
   }

   [[eosio::action]]
   void uniqsecidx() {
      my_table t{"kvtest"_n};

      t.put({
         .primary_key = "bob"_n,
         .foo = "testing",
         .bar = 5,
         .baz = 3
      });

      t.put({
         .primary_key = "bob"_n,
         .foo = "testing",
         .bar = 100,
         .baz = 3
      });
   }

   [[eosio::action]]
   void usecidxerr1() {
      my_table t{"kvtest"_n};

      t.put({
         .primary_key = "carl"_n,
         .foo = "testing",
         .bar = 5,
         .baz = 3
      });
   }

   [[eosio::action]]
   void usecidxerr2() {
      my_table t{"kvtest"_n};

      t.put({
         .primary_key = "alice"_n,
         .foo = "testing",
         .bar = 5,
         .baz = 3
      });
   }
};
