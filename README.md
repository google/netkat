# NetKAT

This is a C++ implementation of NetKAT.

NetKAT is a domain specific language (DSL) and system for specifying,
programming, and reasoning about packet-switched networks. Key features include:

*   Automated reasoning and verification.
*   Modular composition, supporting clean isolation and abstraction.
*   Simple, yet very powerful syntax & semantics.
*   Strong mathematical foundation.

If you want to learn more, you may check out the list of
[publications on NetKAT](#academic-publications-on-netkat) below. In the future,
we also hope to provide a gentler introduction to NetKAT in the form of a
tutorial.

Note: We expect that this NetKAT implementation may diverge from NetKAT as
described [in the literature](#academic-publications-on-netkat) over time, as we
take liberty to optimize and adjust the language for industrial use. Build
rules/targets will also be kept restricted for the time being to discourage any
active external dependents.

## Disclaimer

This is not an officially supported Google product. This project is not eligible
for the
[Google Open Source Software Vulnerability Rewards Program](https://bughunters.google.com/open-source-security).

## Academic Publications on NetKAT

NetKAT was first conceived and studied in academia. Here, we list a small
selection of key publications related to NetKAT.

*   **NetKAT: Semantic Foundations for Networks.** POPL 2014.
    [[PDF]](https://www.cs.cornell.edu/~jnfoster/papers/frenetic-netkat.pdf)
*   **A Fast Compiler for NetKAT.** ICFP 2015.
    [[PDF]](https://www.cs.cornell.edu/~jnfoster/papers/netkat-compiler.pdf)
*   **KATch: A Fast Symbolic Verifier for NetKAT.** PLDI 2024.
    [[PDF]](https://research.google/pubs/katch-a-fast-symbolic-verifier-for-netkat/)

## Contributing

We would love to accept your patches and contributions to this project. Please
familiarize yourself with [our contribution process](docs/CONTRIBUTING.md).

### Source Code Headers

Every file containing source code must include copyright and license
information.

Apache header:

```
Copyright 2024 The NetKAT authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

This can be done automatically using
[addlicense](https://github.com/google/addlicense) as follows: `sh addlicense -c
"The NetKAT authors" -l apache .`
