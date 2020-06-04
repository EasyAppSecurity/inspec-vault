HashiCopr Vault Security Assessment InSpec profile

## Standalone Usage

1. Install [InSpec](https://github.com/chef/inspec) for the profile execution

2. Clone the repository
```
$ git clone https://github.com/EasyAppSecurity/inspec-vault

```
3. Create properties .yml file in **inspec-vault/attributes** folder, where specify Vault settings. 
For example, vault-centos7-test.yml:
```yaml
vault_executable : /home/user/vault # Vault executable
vault_service : vault # Vault service name
vault_service_path : /etc/systemd/system/vault.service # Vault service file path
vault_dir : /opt/vault # Vault directory
vault_user : vault # Vault user name
vault_tlscert : /opt/vault/ssl/server_cert.pem # Vault TLS certificate path
vault_tlskey : /opt/vaul/ssl/server_key.pem # Vault TLS private key path
vault_config : /home/osboxes/config.hcl # Vault configuration (.json or HCL) file

```
4. Execute the profile:
```bash
$ inspec exec inspec-vault --input-file inspec-vault/attributes/vault-centos7-test.yml --reporter html:/tmp/inspec-vault.html

``` 
		
## License and Author

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
