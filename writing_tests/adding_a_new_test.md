# Adding a New Test

All test cases are located in the `tests` directory, which is composed of many subdirectories, each one represents a different test category. The sub-directories may contain sub-categories, if necessary.

```
📁 execution-test-specs/
├─╴📁 tests/                   # test cases
│   ├── 📁 eips/
│   |    ├── 📁 eip4844/
|   |    |    ├── 📄 test_blobhash_opcode.py
|   |    |    └── 📄 test_excess_data_gas.py
|   |    ├── 📄 test_eip3855.py
|   |    └── 📄 test_eip3860.py
│   ├── 📁 example/
│   ├── 📁 security/
│   ├── 📁 vm/
│   ├── 📁 withdrawals/
│   └── 📁 ...
```

Each category/sub-directory may have multiple Python test modules (`*.py`) which in turn may contain many test functions. The test functions themselves are always parametrized by fork (by the framework).

A new test can be added by either:

- Adding a new `test_` python function to an existing file in any of the existing category subdirectories within `tests`.
- Creating a new source file in an existing category, and populating it with the new test function(s).
- Creating an entirely new category by adding a subdirectory in `tests` with the appropriate source files and test functions.
