# Referencing an EIP Spec Version

An Ethereum Improvement Proposal ([ethereum/EIPs](https://github.com/ethereum/EIPs/tree/master/EIPS)) and its SHA digest can be directly referenced within a python test module in order to check whether the test implementation could be out-dated. The test framework automatically generates tests for every module that defines a spec version. If the spec is out-of-date because the SHA of the specified file in the remote repo changes, the corresponding `test_eip_spec_version()` test fails.

<figure markdown>  <!-- markdownlint-disable MD033 (MD033=no-inline-html) -->
  ![Test framework summary for a failing EIP spec version test](./img/eip_reference_spec_console_output.png){ width=auto align=center}
  `<-snip->`
  ![EIP spec version test fail](./img/eip_reference_spec_console_output_fail.png){ width=auto align=center}
</figure>

!!! info ""
    The SHA value is the output from git's `hash-object` command, for example:

    ```console
    git clone git@github.com:ethereum/EIPs
    git hash-object EIPS/EIPS/eip-3651.md
    # output: d94c694c6f12291bb6626669c3e8587eef3adff1
    ```

    and can be retrieved from the remote repo via the Github API on the command-line as following:
    
    ```console
    sudo apt install jq
    curl -s -H "Accept: application/vnd.github.v3+json" \
    https://api.github.com/repos/ethereum/EIPs/contents/EIPS/eip-3651.md |\
    jq -r '.sha'
    # output: d94c694c6f12291bb6626669c3e8587eef3adff1
    ```

## How to Add a Spec Version Check

This check accomplished by adding the following two global variables anywhere in the Python source file:

| Variable Name               | Explanation                                                                                                                                                        |
|-----------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `REFERENCE_SPEC_GIT_PATH`   | The relative path of the EIP markdown file in the [ethereum/EIPs](https://github.com/ethereum/EIPs/) repository, e.g. "`EIPS/eip-1234.md`"                         |
| `REFERENCE_SPEC_VERSION`    | The SHA hash of the latest version of the file retrieved from the Github API:<br>`https://api.github.com/repos/ethereum/EIPs/contents/EIPS/eip-<EIP Number>.md`    |

## Example

Here is an example from [./tests/shanghai/eip3651_warm_coinbase/test_warm_coinbase.py](../tests/shanghai/eip3651_warm_coinbase/test_warm_coinbase/index.md):

```python
REFERENCE_SPEC_GIT_PATH = "EIPS/eip-3651.md"
REFERENCE_SPEC_VERSION = "d94c694c6f12291bb6626669c3e8587eef3adff1"
```

The SHA digest was retrieved [from here](https://api.github.com/repos/ethereum/EIPs/contents/EIPS/eip-3651.md).
