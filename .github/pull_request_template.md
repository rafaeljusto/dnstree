<!--
Describe the big picture of your changes here to communicate to the maintainers why we should accept this pull request.

This text will be included in the changelog. If applicable, include links to documentation or pieces of code.
If your change includes breaking changes please add a code block documenting the breaking change:

```
BREAKING CHANGE: This patch changes the behavior of the flag `foo` to do bar. To keep the existing
behavior please do baz.
```
-->

## Related Issue

<!--
If this pull request

1. is a fix for a known bug, link the issue where the bug was reported in the format of `#1234`;
2. is a fix for a previously unknown bug, explain the bug and how to reproduce it in this pull request;
3. implements a new feature, link the issue containing the design document in the format of `#1234`;
4. improves the documentation, no issue reference is required.

You can discuss changes with maintainers in the Github Discussions in this repository.
-->

## Checklist

<!--
Put an `x` in the boxes that apply. You can also fill these out after creating the PR. If you're unsure about any of
them, don't hesitate to ask. We're here to help! This is simply a reminder of what we are going to look for before merging your code.
-->

- [ ] I have read the [contributing guidelines](../blob/main/CONTRIBUTING.md).
- [ ] My commit subjects carry a [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)
      prefix. The release version is worked out from them, so a feature under a
      plain subject ships as a patch.
- [ ] `make check` passes: it builds, lints, runs the tests under `-race` and
      checks the dependencies for known vulnerabilities.
- [ ] I have added tests that prove my fix is effective or that my feature
      works. The engine is tested offline against `internal/testutil/fakens`, so
      a delegation failure can be reproduced on purpose.
- [ ] I have read the [security policy](../blob/main/SECURITY.md).
- [ ] I confirm that this pull request does not address a security vulnerability.
      If this pull request addresses a security vulnerability,
      I confirm that I got approval (please contact [cadastros@rafael.net.br](mailto:cadastros@rafael.net.br)) from the maintainers to push the changes.
- [ ] I have added the necessary documentation within the code base (if appropriate).

## Further comments

<!--
If this is a relatively large or complex change, kick off the discussion by explaining why you chose the solution
you did and what alternatives you considered, etc...
-->
