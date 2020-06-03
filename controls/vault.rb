# encoding: utf-8
# frozen_string_literal: true

#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

title 'Vault Secure Configuration'

vault_executable = attribute(
  'vault_executable',
  default: '/usr/local/bin/vault',
  description: 'The path on the system where the Vault executable is located'
)

vault_service = attribute(
  'vault_service',
  default: 'vault',
  description: 'The name of the vault service'
)

vault_service_path = attribute(
  'vault_service_path',
  default: '/etc/systemd/system/vault.service',
  description: 'The path on the system where the Vault service configuration file is located'
)

vault_dir = attribute(
  'vault_dir',
  default: '/opt/vault',
  description: 'The system path for the vault installation'
)

vault_user = attribute(
  'vault_user',
  default: 'vault',
  description: 'The system user account that the vault service runs as'
)

vault_tlscert = attribute(
  'vault_tlscert',
  description: 'Path to TLS certificate file',
  default: '/opt/vault/ssl/server_cert.pem'
)

vault_tlskey = attribute(
  'vault_tlskey',
  description: 'Path to TLS key file',
  default: '/opt/vaul/ssl/server_key.pem'
)

vault_config = attribute(
  'vault_config',
  description: 'Path to Vault configuration file',
  default: '/etc/vault/config.hcl'
)

# check if vault exists
only_if do
  command('vault').exist?
end

control 'vault-1.1' do
  impact 1.0
  title 'Verify Vault status attributes'
  desc 'Verify Vault status attributes'

  describe json({ command: 'vault status -format json' }) do
	  its('sealed') { should eq false }
	  its('version') { should cmp >= '1.4.2' }
	  its('storage_type') { should_not eq 'inmem' }
	  its('n') { should cmp >= '3' }
	  its('t') { should cmp >= '2' }
  end

end

control 'vault-1.2' do
  impact 1.0
  title 'Audit Vault executable'
  desc 'Audit all Vault executable activities'

  only_if { os.linux? }
  rule = '-w ' + vault_executable + ' -p rwxa -k vault'
  describe auditd do
    its(:lines) { should include(rule) }
  end
end

control 'vault-1.3' do
  impact 1.0
  title 'Verify that vault configuration directory permissions are set to 640 or more restrictive'
  desc 'Verify that vault configuration directory permissions are set to 640 or more restrictive'

  describe directory(vault_dir) do
	it { should exist }
    its('owner') { should eq vault_user }
    it { should_not be_readable.by('others') }
    it { should_not be_writable.by('others') }
    it { should_not be_executable.by('others') }
  end
end

control 'vault-1.4' do
  impact 1.0
  title 'Audit Vault files and directories'
  desc 'Audit the Vault files and directories'

  only_if { os.linux? }
  rule = '-w ' + vault_dir + ' -p rwxa -k vault'
  describe auditd do
    its(:lines) { should include(rule) }
  end
end

control 'vault-1.5' do
  impact 1.0
  title 'Audit Vault service configuration'
  desc 'Audit Vault service configuration file'

  only_if { os.linux? }
  rule = '-w ' + vault_service_path + ' -p rwxa -k vault'
  describe auditd do
    its(:lines) { should include(rule) }
  end
end

control 'vault-1.6' do
  impact 1.0
  title 'Ensure that the vault service is running'
  desc 'Ensure that the Vault systemd service is running and enabled'

  describe service(vault_service) do
    it { should be_installed }
    it { should be_enabled }
    it { should be_running }
  end
end

control 'vault-1.7' do
  impact 1.0
  title 'Ensure Vault is not running as root'
  desc 'Ensure that the Vault service is not being run as root'

  describe processes('vault') do
    its('users') { should_not eq ['root'] }
  end
end

control 'vault-1.8' do
  impact 1.0
  title 'Ensure swap is disabled on the system'
  desc 'Ensure that swap is disabled on the system to prevent secrets from being written to disk'

  describe command('swapon -s | grep -v Filename') do
    its('exit_status') { should eq 1 }
  end
end

control 'vault-1.9' do
  impact 1.0
  title 'Verify that vault.service file permissions are set to 644 or more restrictive'
  desc 'Verify that the \'vault.service\' file permissions are correctly set to \'644\' or more restrictive.'

  describe file(vault_service_path) do
    it { should exist }
    it { should be_file }
    it { should be_readable.by('owner') }
    it { should be_writable.by('owner') }
    it { should be_readable.by('group') }
    it { should_not be_writable.by('group') }
    it { should be_readable.by('other') }
    it { should_not be_writable.by('other') }
    it { should_not be_executable }
  end
end

control 'vault-1.10' do
  impact 1.0
  title 'Verify that Vault certificate file permissions are set to 400'
  desc 'Verify that Vault certificate file permissions are set to 400'

  describe file(vault_tlskey) do
    it { should exist }
    it { should be_file }
    it { should be_readable.by('owner') }
    it { should_not be_writable.by('owner') }
    it { should_not be_readable.by('group') }
    it { should_not be_writable.by('group') }
    it { should_not be_readable.by('other') }
    it { should_not be_writable.by('other') }
    it { should_not be_executable }
  end
end

control 'vault-1.11' do
  impact 1.0
  title 'Verify that Vault certificate file permissions are set to 400'
  desc 'Verify that Vault certificate file permissions are set to 400'

  describe file(vault_tlscert) do
    it { should exist }
    it { should be_file }
    it { should be_readable.by('owner') }
    it { should_not be_writable.by('owner') }
    it { should_not be_readable.by('group') }
    it { should_not be_writable.by('group') }
    it { should_not be_readable.by('other') }
    it { should_not be_writable.by('other') }
    it { should_not be_executable }
  end
end

control 'vault-1.12' do
  impact 0.5
  title 'Ensure Core Dumps are turned off'
  desc 'A user or administrator that can force a core dump and has access to the resulting file can potentially access Vault encryption keys'

  describe command('ulimit -c') do
    its(:stdout) { should eq '0' }
  end
end

control 'vault-1.13' do
  impact 1.0
  title 'Check Vault configuration file permissions'
  desc 'Check Vault configuration file permissions'
  
  only_if do
    file(vault_config.to_s).exist?
  end
  
  describe file(vault_config) do
    it { should exist }
    it { should be_file }
    it { should be_readable.by('owner') }
    it { should_not be_writable.by('owner') }
    it { should_not be_readable.by('group') }
    it { should_not be_writable.by('group') }
    it { should_not be_readable.by('other') }
    it { should_not be_writable.by('other') }
    it { should_not be_executable }
  end

end

control 'vault-1.14' do
  impact 1.0
  title 'Ensure mlock is not disabled'
  desc 'mlock prevents memory from being swapped to disk. Disabling mlock is not recommended in production, but is fine for local development and testing.'
  
  only_if do
    file(vault_config.to_s).exist?
  end
  
  mlock_disable_option = 'egrep -E \'^(disable_mlock)(\s+)=(\s+)(true)$\' ' + vault_config.to_s
  describe command(mlock_disable_option) do
    its(:stdout) { should be_empty }
  end

end

control 'vault-1.15' do
  impact 1.0
  title 'Check no Clear Text Credentials'
  desc 'DO NOT store your cloud credentials or HSM pin in clear text within the seal stanza. If the Vault server is hosted on the same cloud platform as the KMS service, use the platform-specific identity solutions. If that is not applicable, set the credentials as environment variables (e.g. VAULT_HSM_PIN)'
  
  only_if do
    file(vault_config.to_s).exist?
  end
  
  secret_key_option = 'egrep -E \'(secret_key)(\s*)=(\s*)(.+)\' ' + vault_config.to_s
  describe command(secret_key_option), :sensitive do
    its(:stdout) { should be_empty }
  end
  
  client_secret_option = 'egrep -E \'(client_secret)(\s*)=(\s*)(.+)\' ' + vault_config.to_s
  describe command(client_secret_option), :sensitive do
    its(:stdout) { should be_empty }
  end
  
  credentials_option = 'egrep -E \'(credentials)(\s*)=(\s*)(.+)\' ' + vault_config.to_s
  describe command(credentials_option), :sensitive do
    its(:stdout) { should be_empty }
  end
  
  pin_option = 'egrep -E \'(pin)(\s*)=(\s*)(.+)\' ' + vault_config.to_s
  describe command(pin_option), :sensitive do
    its(:stdout) { should be_empty }
  end

end

control 'vault-1.16' do
  impact 1.0
  title 'Validate Consul storage settings'
  desc 'Validate Consul storage settings'
  
  only_if { 'egrep -E \'(storage)(\s+)("consul")\' ' + vault_config.to_s }
  
  http_scheme_option = 'egrep -E \'(scheme)(\s*)=(\s*)(http)\' ' + vault_config.to_s
  describe command(http_scheme_option) do
    its(:stdout) { should be_empty }
  end
  
  tls_ca_file_option = 'egrep -E \'tls_ca_file\' ' + vault_config.to_s
  describe command(tls_ca_file_option) do
    its(:stdout) { should_not be_empty }
  end
  
  tls_key_file_option = 'egrep -E \'tls_key_file\' ' + vault_config.to_s
  describe command(tls_key_file_option) do
    its(:stdout) { should_not be_empty }
  end
  
  tls_skip_verify_option = 'egrep -E \'(tls_skip_verify)(\s*)=(\s*)(true)\' ' + vault_config.to_s
  describe command(tls_skip_verify_option) do
    its(:stdout) { should be_empty }
  end
  
  tls_min_version_option = 'egrep -E \'(tls_min_version)(\s*)=(\s*)(tls12)\' ' + vault_config.to_s
  describe command(tls_min_version_option) do
    its(:stdout) { should_not be_empty }
  end

end

control 'vault-1.17' do
  impact 0.5
  title 'Ensure SSH / Remote Desktop are disabled'
  desc 'When running a Vault as a single tenant application, users should never access the machine directly. Instead, they should access Vault through its API over the network. Use a centralized logging and telemetry solution for debugging'

  describe command('ps aux | grep sshd') do
    its(:stdout) { should be_empty }
  end
end

control 'vault-1.18' do
  impact 0.5
  title 'Check SELinux / AppArmor status'
  desc 'Using additional mechanisms like SELinux and AppArmor can help provide additional layers of security when using Vault'

  describe.one do
	describe command('sestatus | egrep -E \'(SELinux)(\s*)(status:)(\s+)(enabled)\'') do
		its(:stdout) { should_not be_empty }
	end
	
	describe command('aa-status | egrep -E \'apparmor module is loaded\'') do
		its(:stdout) { should_not be_empty }
	end
  end

end

control 'vault-1.16' do
  impact 1.0
  title 'Validate Etcd storage settings'
  desc 'Validate Etcd storage settings'
  
  only_if { 'egrep -E \'(storage)(\s+)("etcd")\' ' + vault_config.to_s }
  
  http_scheme_option = '(address)(\s*)=(\s*)("http:)' + vault_config.to_s
  describe command(http_scheme_option) do
    its(:stdout) { should be_empty }
  end
  
  tls_ca_file_option = 'egrep -E \'tls_ca_file\' ' + vault_config.to_s
  describe command(tls_ca_file_option) do
    its(:stdout) { should_not be_empty }
  end
  
  tls_key_file_option = 'egrep -E \'tls_key_file\' ' + vault_config.to_s
  describe command(tls_key_file_option) do
    its(:stdout) { should_not be_empty }
  end
  
  password_option = 'egrep -E \'(password)(\s*)=(\s*)(.+)\' ' + vault_config.to_s
  describe command(password_option), :sensitive do
    its(:stdout) { should be_empty }
  end
  
end

control 'vault-1.17' do
  impact 1.0
  title 'Verify Auditing is enabled'
  desc 'Enabling auditing provides a history of all operations performed by Vault and provides a forensics trail in the case of misuse or compromise. Audit logs securely hash any sensitive data, but access should still be restricted to prevent any unintended disclosures.'

  describe command('vault audit list') do
    its(:stdout) { should_not eq 'No audit devices are enabled.' }
  end
  
  describe command('vault audit list -detailed') do
    its(:stdout) { should_not match '(log_raw)(\s*)=(\s*)(true|1)' }
  end
end

control 'vault-1.18' do
  impact 1.0
  title 'Ensure In-Memory Storage Backend is not used'
  desc 'Ensure In-Memory Storage Backend is not used'
  
  inmem_storage = 'egrep -E \'(storage)(\s+)("inmem")\' ' + vault_config.to_s
  describe command(inmem_storage) do
    its(:stdout) { should be_empty }
  end
end
