# chef-alfresco-inspec-mysql Inspec Profile

Inspec profile for [chef-alfresco-db](https://github.com/Alfresco/chef-alfresco-db) cookbook

To use it in your Kitchen suite add:

```
verifier:
  inspec_tests:
    - name: chef-alfresco-inspec-mysql
      git: https://github.com/Alfresco/chef-alfresco-inspec-mysql
```

This Profile depends on [chef-alfresco-inspec-utils](https://github.com/Alfresco/chef-alfresco-inspec-utils) to import libraries and matchers
